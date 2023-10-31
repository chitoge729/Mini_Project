from itertools import permutations

def calculate_distance(route, graph):
    distance = 0
    for i in range(len(route) - 1):
        distance += graph[route[i]][route[i + 1]]
    distance += graph[route[-1]][route[0]]  
    return distance

def brute_force_tsp(graph):
    num_cities = len(graph)
    min_distance = float('inf')
    optimal_route = []
    for perm in permutations(range(num_cities)):
        distance = calculate_distance(perm, graph)
        if distance < min_distance:
            min_distance = distance
            optimal_route = perm
    return optimal_route, min_distance


num_cities = int(input("Enter the number of cities: "))
graph = []
print("Enter the distances between cities:")
for _ in range(num_cities):
    row = list(map(int, input().split()))
    graph.append(row)

optimal_route, min_distance = brute_force_tsp(graph)
print("Optimal Route for Brute Force :", optimal_route)
print("Minimum Distance:", min_distance)
