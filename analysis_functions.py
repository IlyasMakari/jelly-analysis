import pandas as pd
import numpy as np
import sys, os
import re
import json
import networkx as nx
from zipfile import ZipFile
# from itables import init_notebook_mode
# init_notebook_mode(all_interactive=True, connected=True)
import matplotlib.pyplot as plt
from collections import Counter
from IPython.core.display import HTML
from pyvis.network import Network
import signal
import seaborn as sns
from itertools import groupby
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor

possible_package_names = {
    "SNYK-JS-LODASH-73638": ["lodash"],
    "SNYK-JS-MINIMIST-559764": ["minimist"],

    "SNYK-JS-KINDOF-537849": ["kind-of"],
    "SNYK-JS-MINIMATCH-10105": ["minimatch"],
    "SNYK-JS-QS-10407": ["qs"],
    "SNYK-JS-HOEK-12061": ["hoek"],
    "SNYK-JS-DEBUG-10762": ["debug"],
    "SNYK-JS-YARGSPARSER-560381": ["yargs-parser"]
}

possible_module_names = {
    "SNYK-JS-LODASH-73638": ["index.js", "lodash.js", "dist/lodash.js", "merge.js", "mergeWith.js", "_baseMerge.js", "_baseMergeDeep.js", "defaultsDeep.js"],
    "SNYK-JS-MINIMIST-559764": ["index.js"],

    "SNYK-JS-KINDOF-537849": ["index.js"],
    "SNYK-JS-MINIMATCH-10105": ["index.js", "dist/commonjs/index.js", 'minimatch.js'],
    "SNYK-JS-QS-10407": ["index.js", "lib/index.js", 'lib/parse.js', 'lib/querystring.js'],
    "SNYK-JS-HOEK-12061": ["index.js", "lib/index.js"],
    "SNYK-JS-DEBUG-10762": ["index.js", "src/index.js", 'src/common.js', 'src/debug.js', 'lib/debug.js', 'debug.js'],
    "SNYK-JS-YARGSPARSER-560381": ["index.js", 'build/index.cjs']
}

possible_function_names = {
    "SNYK-JS-LODASH-73638": ["defaultsDeep", "merge", "mergeWith"],
    "SNYK-JS-MINIMIST-559764": [],

    "SNYK-JS-KINDOF-537849": ["kindOf", "ctorName"],
    "SNYK-JS-MINIMATCH-10105": ["minimatch", "Minimatch","match", "parse", "make"],
    "SNYK-JS-QS-10407": ["parse", "parseString"],
    "SNYK-JS-HOEK-12061": ["merge", "applyToDefault", "applyToDefaultWithShallow"],
    "SNYK-JS-DEBUG-10762": ["debug"],
    "SNYK-JS-YARGSPARSER-560381": ["Parser", "yargsParser", "parse"]
}

def get_exported_api_objects(filename, packages=None, modules=None, functions=None):
    with open(filename, 'r') as f:
        lines = f.readlines()

    start_index = None
    for i, line in enumerate(lines):
        if "Collecting exported API" in line:
            start_index = i
            break
    if start_index is None:
        return []

    pattern = re.compile(r'.*:.*:.*:.*: <.*>')
    filtered_lines = [line.strip() for line in lines[start_index+1:] if pattern.match(line.strip())]

    results = []
    for line in filtered_lines:
        parts = line.rsplit(': ', 1)
        if len(parts) != 2:
            continue

        path_and_location, pattern_str = parts
        
        segments = path_and_location.split("node_modules/")
        if len(segments) < 2:
            continue
        after_node_modules = segments[-1]

        file_and_locs = after_node_modules.split(':')
        if len(file_and_locs) < 5:
            continue

        file_path = file_and_locs[0]
        start_line, start_col, end_line, end_col = file_and_locs[1], file_and_locs[2], file_and_locs[3], file_and_locs[4]
        location = f"{start_line}:{start_col}:{end_line}:{end_col}"

        file_parts = file_path.split('/', 1)
        if len(file_parts) == 2:
            package_name = file_parts[0]
            module_name = file_parts[1]
        else:
            package_name = file_path
            module_name = ""

        if packages is not None and package_name not in packages:
            continue
        if modules is not None and module_name not in modules:
            continue
        
        # If functions is provided, filter by function names
        if functions is not None:
            # Check if pattern_str ends with any of the given function names or function_name + "()"
            if not any(pattern_str.endswith(fn) or pattern_str.endswith(fn + "()") for fn in functions):
                continue

        results.append({
            "package_name": package_name,
            "module_name": module_name,
            "location": location,
            "pattern": pattern_str
        })

    return results

def parse_vulnerable_calls_file(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    results = []
    line_regex = re.compile(
        r"Detected call to vulnerable function:\s+(.*?)\s+at\s+(.*?)\s+\(vulnerability:\s+(.*?)\)"
    )

    for line in lines:
        line = line.strip()
        match = line_regex.match(line)
        if not match:
            continue

        pattern_str = match.group(1).strip()
        full_path = match.group(2).strip()
        vulnerability = match.group(3).strip()

        segments = full_path.split("node_modules/")
        if len(segments) < 2:
            continue

        after_node_modules = segments[-1]
        file_and_locs = after_node_modules.split(':')
        if len(file_and_locs) < 5:
            continue

        file_path = file_and_locs[0]
        start_line, start_col, end_line, end_col = file_and_locs[1], file_and_locs[2], file_and_locs[3], file_and_locs[4]
        location = f"{start_line}:{start_col}:{end_line}:{end_col}"

        file_parts = file_path.split('/', 1)
        if len(file_parts) == 2:
            package_name = file_parts[0]
            module_name = file_parts[1]
        else:
            package_name = file_path
            module_name = ""

        results.append({
            "package": package_name,
            "module": module_name,
            "vulnerability": vulnerability,
            "pattern": pattern_str,
            "location": location
        })

    # print(results)

    return results

def get_vulnerable_module_names_for_dependency(dependency, functions=None):
  samples = pd.read_json(f"data/jelly_output/output-2024-12-10-2254 approx 1 to 5/$dict.json")
  samples = samples[(samples.success == True) & (samples.dependency == dependency)]
  api = []

  for id in samples.analysis_id:
    if os.path.exists(f"data/jelly_output/output-2024-12-10-2254 approx 1 to 5/{id}.txt"):
      api = api + get_exported_api_objects(f"data/jelly_output/output-2024-12-10-2254 approx 1 to 5/{id}.txt", packages=[dependency], functions=functions)
  return list(set(map(lambda el: el['module_name'], api)))


def extract_jelly_graph(filepath):
  with open(filepath, 'r') as file:
    html_content = file.read()
  pattern = r'const\s+data\s*=\s*({.*?});\s*let\s+graph;'
  match = re.search(pattern, html_content, re.DOTALL)
  if match:
    variable_value = match.group(1)
    json_data = json.loads(variable_value.strip())["graphs"][0]
    # json_vulnerabilities = json_data["vulnerabilities"]
    json_graph = list(map(lambda el: el["data"], json_data["elements"]))
    return json_graph
  else:
    print(f"No match found in: {filepath}")

def extract_pattern_matches(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    pattern = r'Detected call to vulnerable function: (.+?) \(vulnerability: (.+?)\)'
    matches = []
    for line in lines:
        match = re.search(pattern, line)
        if match:
            info_sentence = match.group(1)
            vulnerability_identifier = match.group(2)
            matches.append((vulnerability_identifier, info_sentence.split(" at ")[0], info_sentence.split(" at ")[1]))
    return matches

def ancestors(element, json_graph):
    ancestors_list = []
    if 'parent' not in element:
        return ancestors_list
    parent_element_id = element['parent']
    parent_element = next((e for e in json_graph if e.get('id') == parent_element_id), None)
    if parent_element:
        ancestors_list.append(parent_element)
        ancestors_list.extend(ancestors(parent_element, json_graph))
    return ancestors_list

import re

def find_closest_wrapping_function(location, functions, json_graph, module_name, package_name):
    wrapper = {}
    current_distance = np.inf

    # print(f"find_closest_wrapping_function({location}, {functions}, {json_graph}, {module_name}, {package_name})")

    # Filter functions by module_name and package_name
    filtered_functions = []
    for fun in functions:
        # Retrieve ancestors once and reuse the result
        fun_ancestors = ancestors(fun, json_graph)

        has_module = any(ancestor.get("kind") == "module" and ancestor.get("name") == module_name for ancestor in fun_ancestors)
        has_package = any(ancestor.get("kind") == "package" and ancestor.get("name") == package_name for ancestor in fun_ancestors)

        if has_module and has_package:
            filtered_functions.append(fun)

    for fun in filtered_functions:
        try:
            # Validate that the format matches "141:17:146:2"
            match = re.match(r'^\d+:\d+:\d+:\d+$', fun["name"].split(" ")[1])
            if not match:
                raise ValueError(f"Invalid format in fun['name']: {fun['name']}")

            # Parse the location if the format is valid
            fun_location = list(map(lambda el: int(el), fun["name"].split(" ")[1].split(":")[-4:]))

            max_col = max(location[1], location[3], fun_location[1], fun_location[3])
            location_start = (location[0]-1)*max_col + location[1]
            location_end = (location[2]-1)*max_col + location[3]
            fun_location_start = (fun_location[0]-1)*max_col + fun_location[1]
            fun_location_end = (fun_location[2]-1)*max_col + fun_location[3]
            if location_start >= fun_location_start and location_end <= fun_location_end:
                distance = location_start - fun_location_start
                if distance < current_distance:
                    current_distance = distance
                    wrapper = fun
        except Exception as e:
            print(f"Skipping function due to error: {e}, fun: {fun}")

    return wrapper


def reachable_patterns(matches, json_graph, top_dependent):
  reachable = []
  for pattern_match in matches:
    package = next(filter(lambda el: el["kind"] == 'package' and el["name"] in pattern_match[2], json_graph))
    if top_dependent == package["name"]:
      # The pattern was found on the top dependent, so it will be assumed to be reachable, because why wouldn't it be?
      # [TODO] Maybe check via its module if it's reachable for more accuracy, this could possibly rule out unit tests (not sure)
      reachable.append(pattern_match)
    else:
      possible_modules = filter(lambda el: el["kind"] == 'module' and package in ancestors(el, json_graph), json_graph)
      module = list(filter(lambda el: el["name"] in pattern_match[2], possible_modules))
      if len(module) == 0: continue
      functions = list(filter(lambda el: el["kind"] == 'function' and module[0] in ancestors(el, json_graph), json_graph))
      pattern_location = list(map(lambda el: int(el), pattern_match[2].split(":")[-4:]))
      wrapper_function = find_closest_wrapping_function(pattern_location, functions)
      if "isReachable" in wrapper_function and wrapper_function["isReachable"] == "true":
        reachable.append(pattern_match)
  return reachable


# TODO: check for level because in some cases the package is included 10 times in the graphs at different levels, but we only care about a certain level
def package_reachability_check(vuln_id, json_graph, level):
  found = list(filter(lambda el: el["kind"] == 'package' and el["name"] in possible_package_names[vuln_id] , json_graph))
  reachable = list(filter(lambda el: "isReachable" in el and el["isReachable"] == "true", found))
  return {"found": len(found) > 0, "reachability": len(reachable) > 0}

# TODO: check for level because in some cases the package is included 10 times in the graphs at different levels, but we only care about a certain level
def module_reachability_check(vuln_id, json_graph, level):
  package = list(filter(lambda el: el["kind"] == 'package' and el["name"] in possible_package_names[vuln_id], json_graph))
  found = package and list(filter(lambda el:
                                  el["kind"] == 'module'
                                  and len([x for x in package if x in ancestors(el, json_graph)]) != 0
                                  and el["name"] in possible_module_names[vuln_id], json_graph))
  reachable = list(filter(lambda el: "isReachable" in el and el["isReachable"] == "true", found))
  return {"found": len(found) > 0, "reachability": len(reachable) > 0}


def map_call_elements(json_graph_calls, json_graph):
  mapped_calls = []
  for call in json_graph_calls:
    source_element = next((e for e in json_graph if e.get('id') == call['source']), None)
    target_element = next((e for e in json_graph if e.get('id') == call['target']), None)
    if source_element and target_element:
      mapped_calls.append({
          'kind': call['kind'],
          'source': source_element,
          'target': target_element
      })
  return mapped_calls

def map_with_ancestors(mapped_calls, json_graph):
    result = []
    for call in mapped_calls:
        source_with_ancestors = [call['source']] + ancestors(call['source'], json_graph)
        target_with_ancestors = [call['target']] + ancestors(call['target'], json_graph)
        result.append({
            'kind': call['kind'],
            'source': source_with_ancestors,
            'target': target_with_ancestors
        })
    return result


def create_dag(json_graph, granularity="package", output_txt=None, vuln_id=None):
    """
    Creates a directed graph (DAG) for either 'package' or 'module' elements.

    Parameters:
    - json_graph (list): A list of graph elements (nodes and edges).
    - granularity (str): Determines if the graph is based on 'package' or 'module' ('package' or 'module').

    Returns:
    - networkx.MultiDiGraph: The generated directed acyclic graph.
    """

    # Ensure the granularity is valid
    if granularity not in ["package", "module", "function"]:
        raise ValueError("Granularity must be either 'package' or 'module'")

    # Filter nodes based on granularity (either 'package' or 'module')
    json_graph_elements = list(filter(lambda el: el["kind"] == granularity, json_graph))
    if granularity == "function":
      json_graph_modules = list(filter(lambda el: el["kind"] == 'module', json_graph))

    # Filter calls and requires (these can involve both packages and modules)
    json_graph_calls = list(filter(lambda el: el["kind"] == 'call', json_graph))
    json_graph_requires = list(filter(lambda el: el["kind"] == 'require', json_graph))

    if granularity == "function":
      edges = json_graph_calls
      
      # Create a lookup dict to find nodes by id
      id_to_node = {el["id"]: el for el in json_graph_elements}

      # For each function element, check its parent
      for func_node in json_graph_elements:
          parent_id = func_node.get("parent")
          if parent_id is not None:
              parent_node = id_to_node.get(parent_id)
              # If the parent is also a function, add a "child" edge
              if parent_node and parent_node.get("kind") == "function":
                  edges.append({
                      "source": parent_node["id"],
                      "target": func_node["id"],
                      "kind": "child"
                  })
    else:
      edges = json_graph_calls + json_graph_requires

    # Map source and target to the element they represent
    mapped_calls = map_call_elements(edges, json_graph)

    if granularity == "function":
      simplified_calls = mapped_calls
    else:
      # Map source and target elements to their list of ancestors (including itself)
      mapped_calls_with_ancestors = map_with_ancestors(mapped_calls, json_graph)

      # Map source and target lists to their respective package or module elements
      simplified_calls = []
      for call in mapped_calls_with_ancestors:
          source_element = next((el for el in call['source'] if el['kind'] == granularity), None)
          target_element = next((el for el in call['target'] if el['kind'] == granularity), None)
          if source_element and target_element:
              simplified_calls.append({
                  'kind': call['kind'],
                  'source': source_element,
                  'target': target_element
              })

    # Filter out calls where source and target are the same element (remove self loops)
    filtered_calls = [
        call for call in simplified_calls
        if call['source']['id'] != call['target']['id']
    ]

    # Remove duplicates (calls with the same source/target/kind)
    unique_calls = []
    seen = set()
    for call in filtered_calls:
        source_id = call['source']['id']
        target_id = call['target']['id']
        kind = call['kind']
        if (source_id, target_id, kind) not in seen:
            seen.add((source_id, target_id, kind))
            unique_calls.append(call)

    # Construct a DAG using networkx (MultiDiGraph to handle multiple edges)
    dag = nx.MultiDiGraph()

    

    if granularity == "function":

      # if file exists
      if output_txt is not None and os.path.exists(output_txt):
          
          # Parse the vulnerable calls file and extract locations, modules, and packages
          parsed_calls = parse_vulnerable_calls_file(output_txt)

          # Extract locations, modules, and packages
          locations_modules_packages = [
            (
                list(map(int, call["location"].split(':'))),  # location as list of ints
                call["module"],  # module name
                call["package"]  # package name
            )
            for call in parsed_calls
          ]

          # Find target function IDs, ensuring they belong to the correct module and package
          target_ids = [
              func_id for location, module, package in locations_modules_packages
              if (func_id := find_closest_wrapping_function(location, json_graph_elements, json_graph, module_name=module, package_name=package).get("id", None)) is not None
          ]
          
        #   locations = map(lambda el: list(map(int, el["location"].split(':'))), parse_vulnerable_calls_file(output_txt))          
        #   target_ids = [func_id for location in locations if (func_id := find_closest_wrapping_function(location, json_graph_elements).get("id", None)) is not None]


          pacakge_name = next((el["name"] for el in json_graph if el.get('id') == 1), None) 
          entry_ids = list(set(map(lambda el: el["location"], get_exported_api_objects(output_txt, packages=[pacakge_name]))))
          vuln_functions = possible_function_names[vuln_id]

          for element in json_graph_elements:
              if element["id"] in target_ids:
                  # target ids = function locations where a pattern was found 
                  element["isTarget"] = True
              else:
                  element["isTarget"] = False

              if element["name"].split(" ")[1] in entry_ids:
                  element["isEntry"] = True
              else:
                  element["isEntry"] = False

              if (
                  element["name"].split(" ")[0] in vuln_functions
                  and any(pkg + "@" in element["fullName"] for pkg in possible_package_names[vuln_id])
                  and any(mod in element["fullName"] for mod in possible_module_names[vuln_id])
              ):
                  element["isVulnerable"] = True
              else:
                  element["isVulnerable"] = False


      for element in json_graph_modules:
        dag.add_node(element['fullName'], **element)

    for element in json_graph_elements:
        dag.add_node(element['fullName'], **element)

    # Add edges based on unique calls
    for call in unique_calls:
        source_element = call['source']['fullName']
        target_element = call['target']['fullName']
        kind = call['kind']
        dag.add_edge(source_element, target_element, **call)

    return dag

def create_interactive_graph(dag, filename):
    # Create a pyvis network graph object
    net = Network(height="800px", width="100%", notebook=True, cdn_resources='in_line')

     # Add nodes to the graph
    for node, attrs in dag.nodes(data=True):
        # Check for root node (id == 1) and color it red
        if attrs.get('id') == 1:
            net.add_node(node, label=attrs.get('label', str(node)), title=str(attrs), color="red")
        # Check for module nodes with 'isEntry' == "true" and color it yellow
        elif attrs.get('kind') == 'module' and attrs.get('isEntry') == "true":
            net.add_node(node, label=attrs.get('label', str(node)), title=str(attrs), color="orange")
        elif attrs.get('kind') == 'function' and attrs.get('isEntry') == True:
            net.add_node(node, label=attrs.get('label', str(node)), title=str(attrs), color="yellow") # TODO: allow overlap of entry and target
        elif attrs.get('kind') == 'function' and attrs.get('isVulnerable') == True:
            net.add_node(node, label=attrs.get('label', str(node)), title=str(attrs), color="purple") # TODO: allow overlap of entry and target
        elif attrs.get('kind') == 'function' and attrs.get('isTarget') == True:
            net.add_node(node, label=attrs.get('label', str(node)), title=str(attrs), color="red")
        elif attrs.get('kind') == 'module':
            net.add_node(node, label=attrs.get('label', str(node)), title=str(attrs), color="black")
        else:
            # Default coloring for other nodes
            net.add_node(node, label=attrs.get('label', str(node)), title=str(attrs))

    # Add edges, including the 'kind' information for each edge
    for source, target, key, data in dag.edges(data=True, keys=True):
        edge_label = data.get('kind', 'unknown')  # Use 'kind' to differentiate edges
        net.add_edge(source, target, label=edge_label, title=f"Edge Type: {edge_label}", arrows="to")

    # Set options for layout and interaction
    net.set_options("""
    var options = {
      "nodes": {
        "borderWidth": 2,
        "borderWidthSelected": 4,
        "shape": "dot",
        "size": 15,
        "font": {
          "size": 12
        }
      },
      "edges": {
        "smooth": {
          "type": "continuous"
        },
        "font": {
          "size": 10,
          "align": "horizontal"
        }
      },
      "physics": {
        "enabled": true,
        "solver": "barnesHut",
        "barnesHut": {
          "gravitationalConstant": -5000,
          "springLength": 100,
          "springConstant": 0.01
        }
      }
    }
    """)

    # Save to HTML file on server
    net.show(filename)

    # Read the HTML file and display it in the notebook
    with open(filename, 'r') as f:
        html_content = f.read()

    # Embed HTML into the notebook
    display(HTML(data=html_content))



def check_path_exists(dag, path, include_requires=True):
    """
    Checks if a given path exists in the DAG, considering either 'call' and 'require' edges,
    or only 'call' edges, depending on the value of include_requires.

    Parameters:
    - dag (networkx.DiGraph): The directed graph (DAG) to search within.
    - path (list): The list of nodes representing the path to check.
    - include_requires (bool): If True, include 'require' edges in the search, otherwise only 'call' edges.

    Returns:
    - bool: True if the path exists, False otherwise.
    """
    # Ensure the path has at least two nodes to check for a path
    if len(path) < 2:
        return False

    # Set the allowed edge types based on the include_requires parameter
    edge_types = ['call', 'require'] if include_requires else ['call']

    # Traverse the path and check if there's a valid path through the DAG
    for i in range(len(path) - 1):
        source_node = path[i]
        target_node = path[i + 1]

        # Check if there's an edge of the correct type between consecutive nodes
        found_valid_edge = False
        for _, neighbor, data in dag.out_edges(source_node, data=True):
            if neighbor == target_node and data['kind'] in edge_types:
                found_valid_edge = True
                break

        # If no valid edge is found, return False
        if not found_valid_edge:
            return False

    # If all edges in the path are valid, return True
    return True


def check_module_path_exists(dag, path, vulnerable_node_ids, include_requires=True):
    """
    Checks if a module path exists from any starting node to any ending node in the graph, following
    the package constraints defined in the 'path' argument.

    Parameters:
    - dag (networkx.Graph): The directed graph (DiGraph or MultiGraph) to search within.
    - path (list): A list of ordered package names that restrict the path search.
    - vulnerable_node_ids (list): List of vulnerable module node IDs to check against.
    - include_requires (bool): If True, include 'require' edges; otherwise only 'call' edges.

    Returns:
    - bool: True if a valid path exists, False otherwise.
    """
    # Set the allowed edge types based on the include_requires parameter
    edge_types = ['call', 'require'] if include_requires else ['call']

    # Filter the DAG to include only the relevant edges (based on edge type)
    filtered_dag = dag.copy()
    for u, v, key, data in list(filtered_dag.edges(data=True, keys=True)):
        if data.get('kind') not in edge_types:
            filtered_dag.remove_edge(u, v, key)

    # Find all starting nodes that match the first package in the 'path'
    starting_nodes = [
        node for node, attrs in dag.nodes(data=True)
        if attrs.get('isEntry') == "true" and attrs.get('fullName').split(':')[0] == path[0]
    ]

    # Find all ending nodes (vulnerable modules) based on the 'vulnerable_node_ids'
    ending_nodes = [
        node for node, attrs in dag.nodes(data=True)
        if attrs.get('kind') == 'module' and attrs.get('fullName') in vulnerable_node_ids
    ]

    # If there are no valid starting or ending nodes, return False immediately
    if not starting_nodes or not ending_nodes:
        return False

    # Function to determine the package of a node based on its fullName
    def get_package_name(node):
        return node.split(':')[0]

    # Set up a queue for BFS traversal and a set to track visited nodes
    queue = list(starting_nodes)
    visited = set(starting_nodes)

    # Perform breadth-first search (BFS) to find a valid path
    while queue:
        current_node = queue.pop(0)
        current_package = get_package_name(dag.nodes[current_node]['fullName'])

        # If we reached an ending node, return True
        if current_node in ending_nodes:
            return True

        # Traverse the neighbors of the current node
        for neighbor in filtered_dag.neighbors(current_node):
            neighbor_package = get_package_name(dag.nodes[neighbor]['fullName'])

            # Only continue the traversal if the neighbor is in the same package or the next package in the path
            if neighbor not in visited and (
                neighbor_package == current_package or
                (neighbor_package in path and path.index(neighbor_package) == path.index(current_package) + 1)
            ):
                visited.add(neighbor)
                queue.append(neighbor)

    # If we exhaust the queue without finding a path to an ending node, return False
    return False


class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("TimeoutError: Analysis exceeded 15 minutes")

def analyze_output(path, analyses):
    # analyses["module_found"] = False
    # analyses["package_found"] = False
    # analyses["reachable_module"] = False
    # analyses["pattern_matches"] = 0
    # analyses["reachable_patterns"] = 0
    analyses["error"] = ""
    analyses["handled"] = False

    analyses["metadata_paths"] = 0
    analyses["metadata_paths_found"] = 0
    analyses["metadata_paths_found_only_calls"] = 0

    analyses["package_count"] = 0
    analyses["module_count"] = 0
    analyses["function_count"] = 0
    analyses["call_count"] = 0

    def fcontents(fpath):
        with open(fpath, 'r') as file:
            content = file.read()
        return content

    countr = 0
    total_size = len(analyses)

    def analyze_single_id(analysis_id, row):
        nonlocal countr
        countr = countr + 1
        log_line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Analyzing analysis_id: {analysis_id} ({countr}/{total_size})"
        print(log_line)
        with open(f"log.txt", 'a') as file:
            file.write(log_line + '\n')
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(10 * 60)  # Set the alarm for 5 minutes per analysis_id
        try:
            if os.path.isfile(f"{path}/{analysis_id}-result.csv"):
                csv_df = pd.read_csv(f"{path}/{analysis_id}-result.csv")
                first_row = csv_df.iloc[0].to_dict()
                for column, value in first_row.items():
                    analyses.loc[analyses.analysis_id == analysis_id, column] = value
            elif os.path.isfile(f"{path}/{analysis_id}"):
                with open(f"{path}/{analysis_id}", 'r') as file:
                    error = file.read()
                analyses.loc[analyses.analysis_id == analysis_id, "error"] = error
            elif os.path.isfile(f"{path}/{analysis_id}.txt") and not os.path.isfile(f"{path}/{analysis_id}.html"):
                analyses.loc[analyses.analysis_id == analysis_id, "error"] = fcontents(f"{path}/{analysis_id}.txt")
            else:

                json_graph = extract_jelly_graph(f"{path}/{analysis_id}.html")
                json_graph_packages = list(filter(lambda el: el["kind"] == 'package', json_graph))
                json_graph_modules = list(filter(lambda el: el["kind"] == 'module', json_graph))
                json_graph_functions = list(filter(lambda el: el["kind"] == 'function', json_graph))
                json_graph_calls = list(filter(lambda el: el["kind"] == 'call', json_graph))

                # Create DAG from json_graph
                package_dag = create_dag(json_graph, granularity='package')

                # Retrieve and save metadata paths to vulnerabilities
                with open(f"{path}/{analysis_id}-paths.json", 'r') as f:
                  metadata_paths = json.load(f)
                filtered_meta_paths = metadata_paths.get("namePathsFiltered") # filtered = only include paths of the correct length according to the analysis level
                analyses.loc[analyses.analysis_id == analysis_id, "metadata_paths"] = len(filtered_meta_paths)
                analyses.loc[analyses.analysis_id == analysis_id, "metadata_paths_json"] = json.dumps(filtered_meta_paths)

                # Check if the package paths exist in the call graph and store the counts
                metadata_paths_found = []
                metadata_paths_found_only_calls = []
                for meta_path in filtered_meta_paths:
                    if check_path_exists(package_dag, meta_path, include_requires=True):
                        metadata_paths_found.append(meta_path)
                    if check_path_exists(package_dag, meta_path, include_requires=False):
                        metadata_paths_found_only_calls.append(meta_path)
                analyses.loc[analyses.analysis_id == analysis_id, "metadata_paths_found"] = len(metadata_paths_found)
                analyses.loc[analyses.analysis_id == analysis_id, "metadata_paths_found_only_calls"] = len(metadata_paths_found_only_calls)
                analyses.loc[analyses.analysis_id == analysis_id, "metadata_paths_found_json"] = json.dumps(metadata_paths_found)
                analyses.loc[analyses.analysis_id == analysis_id, "metadata_paths_found_only_calls_json"] = json.dumps(metadata_paths_found_only_calls)


                # Check if the module paths exist in the call graph and store the counts
                vulnerable_module_names = []
                vulnerable_package_names = list(set(path[-1] for path in filtered_meta_paths))
                for package_name in vulnerable_package_names:
                    for module_name in possible_module_names[row['vuln_id'].iloc[0]]:
                        vulnerable_module_names.append(f"{package_name}:{module_name}")
                module_dag = create_dag(json_graph, granularity='module')
                package_module_paths_found = []
                package_module_paths_only_calls_found = []
                for vpath in metadata_paths_found:
                    if check_module_path_exists_dfs(module_dag, vpath, vulnerable_module_names, include_requires=True):
                        package_module_paths_found.append(vpath)
                for vpath in metadata_paths_found_only_calls:
                    if check_module_path_exists_dfs(module_dag, vpath, vulnerable_module_names, include_requires=False):
                        package_module_paths_only_calls_found.append(vpath)
                analyses.loc[analyses.analysis_id == analysis_id, "package_module_paths_found"] = len(package_module_paths_found)
                analyses.loc[analyses.analysis_id == analysis_id, "package_module_paths_only_calls_found"] = len(package_module_paths_only_calls_found)
                analyses.loc[analyses.analysis_id == analysis_id, "package_module_paths_found_json"] = json.dumps(package_module_paths_found)
                analyses.loc[analyses.analysis_id == analysis_id, "package_module_paths_only_calls_found_json"] = json.dumps(package_module_paths_only_calls_found)

                # Check if the function paths exist in the call graph and store the counts
                vuln_id = row["vuln_id"].iloc[0]
                function_dag = create_dag(json_graph, granularity='function', output_txt=f"{path}/{analysis_id}.txt", vuln_id=vuln_id)
                package_function_paths_found = []
                package_function_paths_only_patterns_found = []
                for vpath in metadata_paths_found:
                    if check_function_path_exists_dfs(function_dag, vpath, include_children=True, only_patterns=False):
                        package_function_paths_found.append(vpath)
                for vpath in metadata_paths_found_only_calls:
                    if check_function_path_exists_dfs(function_dag, vpath, include_children=True, only_patterns=True):
                        package_function_paths_only_patterns_found.append(vpath)
                analyses.loc[analyses.analysis_id == analysis_id, "package_function_paths_found"] = len(package_function_paths_found)
                analyses.loc[analyses.analysis_id == analysis_id, "package_function_paths_only_patterns_found"] = len(package_function_paths_only_patterns_found)
                analyses.loc[analyses.analysis_id == analysis_id, "package_function_paths_found_json"] = json.dumps(package_function_paths_found)
                analyses.loc[analyses.analysis_id == analysis_id, "package_function_paths_only_patterns_found_json"] = json.dumps(package_function_paths_only_patterns_found)

                # Get and store the module/function/edge counts
                module_counts = []
                function_counts = []
                edge_counts = []
                for meta_path in filtered_meta_paths:
                    module_counts.append(module_count_in_path(json_graph, meta_path))
                    function_counts.append(function_count_in_path(json_graph, meta_path))
                    edge_counts.append(edge_count_in_path(json_graph, meta_path))
                analyses.loc[analyses.analysis_id == analysis_id, "module_counts_json"] = json.dumps(module_counts)
                analyses.loc[analyses.analysis_id == analysis_id, "function_counts_json"] = json.dumps(function_counts)
                analyses.loc[analyses.analysis_id == analysis_id, "edge_counts_json"] = json.dumps(edge_counts)

                interesting_packages = set(item for sublist in filtered_meta_paths for item in sublist)
                analyses.loc[analyses.analysis_id == analysis_id, "module_count_interesting"] = module_count_in_path(json_graph, interesting_packages)
                analyses.loc[analyses.analysis_id == analysis_id, "function_count_interesting"] = function_count_in_path(json_graph, interesting_packages)
                analyses.loc[analyses.analysis_id == analysis_id, "edge_count_interesting"] = edge_count_in_path(json_graph, interesting_packages)


                # save json_graph to json file
                # with open(f"{analysis_id}.json", 'w') as file:
                #     json.dump(json_graph, file)

                analyses.loc[analyses.analysis_id == analysis_id, "package_count"] = len(json_graph_packages)
                analyses.loc[analyses.analysis_id == analysis_id, "module_count"] = len(json_graph_modules)
                analyses.loc[analyses.analysis_id == analysis_id, "function_count"] = len(json_graph_functions)
                analyses.loc[analyses.analysis_id == analysis_id, "call_count"] = len(json_graph_calls)

                # matches = extract_pattern_matches(f"{path}/{analysis_id}.txt")
                # analyses.loc[analyses.analysis_id == analysis_id, "pattern_matches"] = len(matches)
                # analyses.loc[analyses.analysis_id == analysis_id, "reachable_patterns"] = len(reachable_patterns(matches, json_graph, row["package"].iloc[0]))
                # prc = package_reachability_check(row["vuln_id"].iloc[0], json_graph, row["level"])
                # mrc = module_reachability_check(row["vuln_id"].iloc[0], json_graph, row["level"])
                # analyses.loc[analyses.analysis_id == analysis_id, "package_found"] = prc["found"]
                # analyses.loc[analyses.analysis_id == analysis_id, "reachable_package"] = prc["reachability"]
                # analyses.loc[analyses.analysis_id == analysis_id, "module_found"] = mrc["found"]
                # analyses.loc[analyses.analysis_id == analysis_id, "reachable_module"] = mrc["reachability"]
        except TimeoutException:
            analyses.loc[analyses.analysis_id == analysis_id, "error"] = "TimeoutError: Analysis exceeded 5 minutes"
        finally:
            signal.alarm(0)  # Disable the alarm after each analysis_id
            analyses.loc[analyses.analysis_id == analysis_id, "handled"] = True

    # Loop over each analysis_id and apply the timeout per id
    for analysis_id in analyses["analysis_id"].to_list():
        row = analyses[analyses.analysis_id == analysis_id]
        analyze_single_id(analysis_id, row)

    return analyses



def process_row(row_dict, output_folder):
    """
    Processes a single row by calling the actual `analyze_output` function.
    """
    # Convert the row dictionary back to a DataFrame with one row
    row_df = pd.DataFrame([row_dict])

    # Call the actual analyze_output function
    updated_row_df = analyze_output(output_folder, row_df)

    # Extract the updated row as a dictionary and return it
    return updated_row_df.iloc[0].to_dict()

def process_row_wrapper(args):
    """
    Wrapper to unpack arguments for process_row.
    """
    return process_row(*args)


def analyze_output_in_parallel(output_folder, analyses, threads=4):
    """
    Parallelized wrapper for analyze_output.

    Parameters:
    - output_folder (str): Path to the output folder.
    - analyses (pd.DataFrame): DataFrame containing rows to analyze.
    - threads (int): Number of threads/processes to use for parallel processing.

    Returns:
    - pd.DataFrame: The updated DataFrame.
    """

    # Ensure the column exists in the DataFrame
    for newcol in ["module_counts_json", "function_counts_json", "edge_counts_json", "module_count_interesting", "function_count_interesting", "edge_count_interesting", "error", "handled", "metadata_paths", "metadata_paths_json", "metadata_paths_found", "metadata_paths_found_only_calls", "metadata_paths_found_json", "metadata_paths_found_only_calls_json", "package_count", "module_count", "function_count", "call_count", "package_module_paths_found", "package_module_paths_only_calls_found", "package_module_paths_found_json", "package_module_paths_only_calls_found_json", "package_function_paths_found", "package_function_paths_only_patterns_found", "package_function_paths_found_json", "package_function_paths_only_patterns_found_json"]:
        if newcol not in analyses.columns:
            analyses[newcol] = None

    # Convert DataFrame rows to dictionaries for compatibility
    rows = [row.to_dict() for _, row in analyses.iterrows()]

    with ProcessPoolExecutor(max_workers=threads) as executor:
        # Pass rows as dictionaries along with output_folder
        updated_rows = list(executor.map(process_row_wrapper, [(row, output_folder) for row in rows]))

    # Update the original DataFrame with the modified rows
    for i, updated_row in enumerate(updated_rows):
        for col, value in updated_row.items():
            analyses.iat[i, analyses.columns.get_loc(col)] = value

    return analyses


def check_module_path_exists_dfs(dag, path, vulnerable_node_ids, include_requires=True):
    """
    Checks if a module path exists from any starting node to any ending node in the graph, following
    the package constraints defined in the 'path' argument, using DFS.

    Parameters:
    - dag (networkx.Graph): The directed graph (DiGraph or MultiGraph) to search within.
    - path (list): A list of ordered package names that restrict the path search.
    - vulnerable_node_ids (list): List of vulnerable module node IDs to check against.
    - include_requires (bool): If True, include 'require' edges; otherwise only 'call' edges.

    Returns:
    - bool: True if a valid path exists, False otherwise.
    """
    # Set the allowed edge types based on the include_requires parameter
    edge_types = ['call', 'require'] if include_requires else ['call']

    # Filter the DAG to include only the relevant edges (based on edge type)
    filtered_dag = dag.copy()
    for u, v, key, data in list(filtered_dag.edges(data=True, keys=True)):
        if data.get('kind') not in edge_types:
            filtered_dag.remove_edge(u, v, key)

    # Find all starting nodes that match the first package in the 'path'
    starting_nodes = [
        node for node, attrs in dag.nodes(data=True)
        if attrs.get('isEntry') == "true" and attrs.get('fullName').split(':')[0] == path[0]
    ]

    # Find all ending nodes (vulnerable modules) based on the 'vulnerable_node_ids'
    ending_nodes = [
        node for node, attrs in dag.nodes(data=True)
        if attrs.get('kind') == 'module' and attrs.get('fullName') in vulnerable_node_ids
    ]

    # If there are no valid starting or ending nodes, return False immediately
    if not starting_nodes or not ending_nodes:
        return False

    # Function to determine the package of a node based on its fullName
    def get_package_name(node):
        return node.split(':')[0]

    # Recursive DFS function
    def dfs(current_node, current_package_index, visited):
        # If we've reached an ending node, return True
        if current_node in ending_nodes:
            return True

        # Mark the current node as visited
        visited.add(current_node)

        # Traverse neighbors
        for neighbor in filtered_dag.neighbors(current_node):
            if neighbor in visited:
                continue

            neighbor_package = get_package_name(dag.nodes[neighbor]['fullName'])

            # Allow traversal only if the neighbor is in the same package or the next package in the path
            if (neighbor_package == path[current_package_index] or
                (current_package_index + 1 < len(path) and neighbor_package == path[current_package_index + 1])):
                # Determine the next package index (increment only if moving to the next package)
                next_package_index = current_package_index
                if (current_package_index + 1 < len(path) and neighbor_package == path[current_package_index + 1]):
                    next_package_index += 1

                # Recur to check paths from the neighbor
                if dfs(neighbor, next_package_index, visited):
                    return True

        # Backtrack
        visited.remove(current_node)
        return False

    # Perform DFS from each starting node
    for start_node in starting_nodes:
        if dfs(start_node, 0, set()):  # Start with the first package in the path
            return True

    # If no path is found, return False
    return False






def check_function_path_exists_dfs(dag, path, include_children=True, only_patterns=False):
    """
    Checks if a function path exists from any starting node to any ending node in the graph, following
    the package constraints defined in the 'path' argument, using DFS.

    Parameters:
    - dag (networkx.Graph): The directed graph (DiGraph or MultiGraph) to search within.
    - path (list): A list of ordered package names that restrict the path search.
    - include_children (bool): If True, include 'child' edges; otherwise only 'call' edges.

    Returns:
    - bool: True if a valid path exists, False otherwise.
    """
    # Set the allowed edge types based on the include_children parameter
    edge_types = ['call', 'child'] if include_children else ['call']
    target_types = ['isTarget'] if only_patterns else ['isTarget', 'isVulnerable']

    # Filter the DAG to include only the relevant edges (based on edge type)
    filtered_dag = dag.copy()
    for u, v, key, data in list(filtered_dag.edges(data=True, keys=True)):
        if data.get('kind') not in edge_types:
            filtered_dag.remove_edge(u, v, key)

    # Find all starting nodes that match the first package in the 'path'
    starting_nodes = [
        node for node, attrs in dag.nodes(data=True)
        if attrs.get('isEntry') == "true" or attrs.get('isEntry') == True
    ]

    # Find all ending nodes (location of vulnerable patterns)
    ending_nodes = [
        node for node, attrs in dag.nodes(data=True)
        if any(attrs.get(item) == True for item in target_types)
    ]

    # If there are no valid starting or ending nodes, return False immediately
    if not starting_nodes or not ending_nodes:
        return False

    # Function to determine the package of a node based on its fullName
    def get_package_name(node):
      
      if "'" in node:
        parts = node.split("'")
        node = parts[-1]

      name = node.split(':')[0]

      return name

    # Recursive DFS function
    def dfs(current_node, current_package_index, visited):
        # If we've reached an ending node, return True
        if current_node in ending_nodes:
            return True

        # Mark the current node as visited
        visited.add(current_node)

        # Traverse neighbors
        for neighbor in filtered_dag.neighbors(current_node):
            if neighbor in visited:
                continue

            neighbor_package = get_package_name(dag.nodes[neighbor]['fullName'])

            # Allow traversal only if the neighbor is in the same package or the next package in the path
            if (neighbor_package == path[current_package_index] or
                (current_package_index + 1 < len(path) and neighbor_package == path[current_package_index + 1])):
                # Determine the next package index (increment only if moving to the next package)
                next_package_index = current_package_index
                if (current_package_index + 1 < len(path) and neighbor_package == path[current_package_index + 1]):
                    next_package_index += 1

                # Recur to check paths from the neighbor
                if dfs(neighbor, next_package_index, visited):
                    return True

        # Backtrack
        visited.remove(current_node)
        return False

    # Perform DFS from each starting node
    for start_node in starting_nodes:
        if dfs(start_node, 0, set()):  # Start with the first package in the path
            return True

    # If no path is found, return False
    return False



def module_count_in_path(json_graph, path):
    """
    Count the number of modules present in the path.

    Parameters:
        json_graph (list): A list of dictionaries representing the nodes and edges of the graph.
        path (list): A list of strings representing the package path (e.g., ['pkg1@1.0.0', 'pkg2@2.0.0']).

    Returns:
        int: The count of modules in the path.
    """
    # Filter out all modules in the json_graph
    modules = [node for node in json_graph if node.get("kind") == "module"]

    # Retrieve parent package information for each module
    module_count = 0
    for module in modules:
        parent_id = module.get("parent")
        
        # Find the parent package node
        parent_package = next((node for node in json_graph if node.get("id") == parent_id and node.get("kind") == "package"), None)
        
        if parent_package and parent_package.get("fullName") in path:
            module_count += 1

    return module_count


def edge_count_in_path(json_graph, packages):
    """
    Count the number of edges where the source or target corresponds to a package in the given list of packages,
    and exclude edges where the source ancestor list contains a package not in the given packages list.

    Parameters:
        json_graph (list): A list of dictionaries representing the nodes and edges of the graph.
        packages (list): A list of package names to filter (e.g., ['pkg1@1.0.0', 'pkg2@2.0.0']).

    Returns:
        int: The count of edges in the path.
    """
    # Filter for call elements from the json_graph
    calls = [node for node in json_graph if node.get("kind") == "call"]

    # Map call elements to their actual elements
    mapped_calls = map_call_elements(calls, json_graph)

    # Map the calls with ancestors
    calls_with_ancestors = map_with_ancestors(mapped_calls, json_graph)

    # Count edges where the source and target meet the criteria
    edge_count = 0
    for call in calls_with_ancestors:
        source_ancestors = call.get("source", [])
        target_ancestors = call.get("target", [])

        # Check if the source ancestor list only contains packages in the given packages list
        source_only_in_packages = all(
            ancestor.get("kind") != "package" or ancestor.get("fullName") in packages
            for ancestor in source_ancestors
        )

        # Check if any ancestor in the target is a package in the given packages list
        target_matches = any(
            ancestor.get("kind") == "package" and ancestor.get("fullName") in packages
            for ancestor in target_ancestors
        )

        # Keep the edge only if the source ancestors are all valid and the target matches
        if source_only_in_packages and target_matches:
            edge_count += 1

    return edge_count


def function_count_in_path(json_graph, packages):
    """
    Count the number of functions in the graph where an ancestor package has a fullName in the given packages list.

    Parameters:
        json_graph (list): A list of dictionaries representing the nodes and edges of the graph.
        packages (list): A list of package names to filter (e.g., ['pkg1@1.0.0', 'pkg2@2.0.0']).
    Returns:
        int: The count of functions in the path.
    """
    # Filter for function elements from the json_graph
    functions = [node for node in json_graph if node.get("kind") == "function"]

    # Count functions whose ancestors include a package in the given packages list
    function_count = 0
    for function in functions:
        function_ancestors = ancestors(function, json_graph)

        # Check if any ancestor has kind "package" and a fullName in the given packages list
        matches = any(
            ancestor.get("kind") == "package" and ancestor.get("fullName") in packages
            for ancestor in function_ancestors
        )

        if matches:
            function_count += 1

    return function_count



import argparse
import json
import os
import sys

def analyze_and_save(json_object, output_folder):
    # Parse the JSON object
    try:
        obj = json.loads(json_object)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON object provided. {e}")
        sys.exit(1)

    # Check if "success" is true
    if not obj.get("success", False):
        print("Error: The JSON object does not have 'success': true.")
        sys.exit(1)

    # Convert the object into a DataFrame with one row
    df = pd.DataFrame([obj])

    # Use the analyze_output function
    analyzed_df = analyze_output(output_folder, df)

    # Save the resulting DataFrame as a CSV file
    output_path = os.path.join(output_folder, f"{obj.get('analysis_id')}-result.csv")
    analyzed_df.to_csv(output_path, index=False)
    print(f"Result saved to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Analyze a JSON object and save the result as a CSV.")
    parser.add_argument("output_folder", type=str, help="Folder to save the result CSV")
    parser.add_argument("json_object", type=str, help="JSON object as a string")
    args = parser.parse_args()

    analyze_and_save(args.json_object, args.output_folder)

if __name__ == "__main__":
    main()