import networkx as nx
import json
import numpy as np
from collections import defaultdict
import random
from datetime import datetime
import pandas as pd
import os  # 新增：用于路径验证
from pathlib import Path  # 新增：用于路径安全检查

def convert_time_to_timestamp(time_str):
    """将时间字符串转换为时间戳

    Args:
        time_str: 时间字符串，格式为 'YYYY-MM-DD HH:MM:SS'

    Returns:
        浮点数时间戳，若转换失败则返回 0
    """
    if not time_str:
        return 0
    try:
        dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        return dt.timestamp()
    except (ValueError, TypeError):  # 修改：明确捕获异常
        return 0

def convert_gml_to_graphsage(gml_file, features_file, output_prefix, train_ratio=0.7, val_ratio=0.15):
    """将 GML 图转换为 GraphSAGE 格式并保存输出

    Args:
        gml_file: 输入 GML 文件路径
        features_file: 节点特征 JSON 文件路径
        output_prefix: 输出文件前缀
        train_ratio: 训练集比例（默认 0.7）
        val_ratio: 验证集比例（默认 0.15）
    """

    # 新增：验证输入文件路径
    if not os.path.exists(gml_file) or not os.path.exists(features_file):
        raise FileNotFoundError("输入文件不存在")
    if not Path(gml_file).resolve().is_relative_to(Path.cwd()) or \
       not Path(features_file).resolve().is_relative_to(Path.cwd()):
        raise ValueError("无效文件路径（可能存在路径遍历风险）")
    # 安全性：防止路径遍历攻击
    for file_path in [gml_file, features_file]:
        resolved = Path(file_path).resolve()
        if not resolved.is_relative_to(Path.cwd()):
            raise ValueError(f"文件路径非法：{file_path}")
    # 新增：确保输出目录存在

    output_dir = os.path.dirname(output_prefix)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    # 读取图结构
    G = nx.read_gml(gml_file)

    # 加载节点特征
    try:
        with open(features_file, 'r') as f:
            node_features = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"节点特征 JSON 无效：{e}")


    nodes = list(G.nodes())
    id_map = {node: i for i, node in enumerate(nodes)}

    # 构造标签映射
    class_map = {}
    for node in nodes:
        node_type = G.nodes[node].get('type')
        if node_type in ['fqdn', 'apex']:
            is_hijacked = G.nodes[node].get('hijacked', False)
            class_map[node] = 1 if is_hijacked else 0
        else:
            class_map[node] = -1

    num_nodes = len(nodes)
    features = {}

    for node in nodes:
        node_type = G.nodes[node].get('type')
        features[node] = [
            float(G.nodes[node].get('count', 0)),
            convert_time_to_timestamp(G.nodes[node].get('last_seen', None))
        ]

    feature_dim = len(features[nodes[0]])
    feats = np.zeros((num_nodes, feature_dim))
    for node, idx in id_map.items():
        feats[idx] = features[node]

    # 数据集划分
    domain_nodes = [node for node in nodes if G.nodes[node]['type'] in ['fqdn', 'apex']]
    random.shuffle(domain_nodes)
    train_size = int(len(domain_nodes) * train_ratio)
    val_size = int(len(domain_nodes) * val_ratio)

    train_nodes = domain_nodes[:train_size]
    val_nodes = domain_nodes[train_size:train_size + val_size]
    test_nodes = domain_nodes[train_size + val_size:]

    for node in nodes:
        G.nodes[node]['val'] = node in val_nodes
        G.nodes[node]['test'] = node in test_nodes

    # 保存图结构等信息
    graph_data = nx.node_link_data(G, edges="links")
    with open(f"{output_prefix}-G.json", 'w') as f:
        json.dump(graph_data, f)
    with open(f"{output_prefix}-id_map.json", 'w') as f:
        json.dump(id_map, f)
    with open(f"{output_prefix}-class_map.json", 'w') as f:
        json.dump(class_map, f)
    np.save(f"{output_prefix}-feats.npy", feats)

    nodes_data = []
    for node in nodes:
        node_type = G.nodes[node]['type']
        node_data = {
            'node_id': node,
            'feat_domain': 1 if node_type in ['fqdn', 'apex'] else 0,
            'feat_ip': 1 if node_type == 'ip' else 0,
            'feat_subnet': 1 if node_type == 'subnet' else 0,
            'label': class_map[node]
        }
        for i, feat in enumerate(features[node]):
            node_data[f'feat_{i}'] = feat
        nodes_data.append(node_data)
    pd.DataFrame(nodes_data).to_csv(f"{output_prefix}-nodes.csv", index=False)

    # 边 CSV
    edges_data = []
    for u, v, data in G.edges(data=True):
        edge_type = data.get('relation', 'to')
        edge_data = {
            'source': u,
            'target': v,
            'edge_type': {
                'resolves_to': 0,
                'belongs_to': 1,
                'fqdnapex': 2,
                'similar_apex': 3,
                'similar_all': 4
            }.get(edge_type, 0)
        }
        edges_data.append(edge_data)
    pd.DataFrame(edges_data).to_csv(f"{output_prefix}-edges.csv", index=False)

    # 控制台输出信息
    hijacked_count = sum(1 for node in domain_nodes if class_map[node] == 1)
    normal_count = sum(1 for node in domain_nodes if class_map[node] == 0)
    print(f"数据转换完成！输出文件前缀：{output_prefix}")
    print(f"节点数量：{num_nodes}")
    print(f"特征维度：{feature_dim}")
    print(f"域名节点数量：{len(domain_nodes)}")
    print(f"训练集大小：{len(train_nodes)}")
    print(f"验证集大小：{len(val_nodes)}")
    print(f"测试集大小：{len(test_nodes)}")
    print(f"被劫持域名数量：{hijacked_count}")
    print(f"正常域名数量：{normal_count}")

if __name__ == "__main__":
    gml_file = "your_graph.gml"
    features_file = "node_features.json"
    output_prefix = "graph_data"
    convert_gml_to_graphsage(gml_file, features_file, output_prefix)
