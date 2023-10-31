
def nearest_neighbor_tsp(graph):
    num_cities = len(graph)
    visited = [False] * num_cities
    route = []
    current_city = 0  
    total_distance = 0

    for _ in range(num_cities - 1):
        route.append(current_city)
        visited[current_city] = True
        nearest_city = min((i for i in range(num_cities) if not visited[i]), key=lambda x: graph[current_city][x])
        total_distance += graph[current_city][nearest_city]
        current_city = nearest_city

    route.append(current_city)
    total_distance += graph[current_city][route[0]]
    return route, total_distance


num_cities = int(input("Enter the number of cities: "))
graph = []
print("Enter the distances between cities:")
for _ in range(num_cities):
    row = list(map(int, input().split()))
    graph.append(row)

optimal_route, min_distance = nearest_neighbor_tsp(graph)
print("Optimal Route for Nearest Neighbour :", optimal_route)
print("Minimum Distance:", min_distance)
