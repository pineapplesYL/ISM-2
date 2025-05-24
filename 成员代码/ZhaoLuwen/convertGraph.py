import networkx as nx
import json
import numpy as np
from collections import defaultdict
import random
from datetime import datetime
import pandas as pd
import os  # 用于路径验证
from pathlib import Path  # 用于路径安全检查


def convert_time_to_timestamp(time_str):
    """
    将时间字符串转换为时间戳

    Args:
        time_str (str): 时间字符串，格式为 'YYYY-MM-DD HH:MM:SS'

    Returns:
        float: 时间戳，若转换失败则返回 0
    """
    if not time_str:
        return 0
    try:
        dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0


def convert_gml_to_graphsage(gml_file, features_file, output_prefix, train_ratio=0.7, val_ratio=0.15):
    """
    将 GML 图转换为 GraphSAGE 格式并保存输出文件

    Args:
        gml_file (str): 输入 GML 图文件路径
        features_file (str): 节点特征 JSON 文件路径
        output_prefix (str): 输出文件前缀
        train_ratio (float): 训练集比例（默认 0.7）
        val_ratio (float): 验证集比例（默认 0.15）
    """
    # 安全校验：检查输入文件是否存在
    if not os.path.exists(gml_file) or not os.path.exists(features_file):
        raise FileNotFoundError("输入文件不存在")

    # 路径合法性检查：防止路径遍历
    for file_path in [gml_file, features_file]:
        resolved = Path(file_path).resolve()
        if not resolved.is_relative_to(Path.cwd()):
            raise ValueError(f"文件路径非法：{file_path}")

    # 若输出目录不存在则自动创建
    output_dir = os.path.dirname(output_prefix)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    # 读取图结构
    G = nx.read_gml(gml_file)

    # 加载节点特征文件
    try:
        with open(features_file, 'r') as f:
            node_features = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"节点特征 JSON 无效：{e}")

    nodes = list(G.nodes())
    id_map = {node: i for i, node in enumerate(nodes)}

    # 构建类别映射
    class_map = {}
    for node in nodes:
        node_type = G.nodes[node].get('type')
        if node_type in ['fqdn', 'apex']:
            is_hijacked = G.nodes[node].get('hijacked', False)
            class_map[node] = 1 if is_hijacked else 0
        else:
            class_map[node] = -1  # 非目标类型节点标记为 -1

    # 构造节点特征矩阵
    features = {}
    for node in nodes:
        node_type = G.nodes[node].get('type')
        count = float(G.nodes[node].get('count', 0))
        last_seen = convert_time_to_timestamp(G.nodes[node].get('last_seen', None))
        features[node] = [count, last_seen]

    feature_dim = len(features[nodes[0]])
    feats = np.zeros((len(nodes), feature_dim))
    for node, idx in id_map.items():
        feats[idx] = features[node]

    # 划分训练/验证/测试集
    domain_nodes = [node for node in nodes if G.nodes[node].get('type') in ['fqdn', 'apex']]
    random.shuffle(domain_nodes)
    train_size = int(len(domain_nodes) * train_ratio)
    val_size = int(len(domain_nodes) * val_ratio)

    train_nodes = domain_nodes[:train_size]
    val_nodes = domain_nodes[train_size:train_size + val_size]
    test_nodes = domain_nodes[train_size + val_size:]

    for node in nodes:
        G.nodes[node]['val'] = node in val_nodes
        G.nodes[node]['test'] = node in test_nodes

    # 保存图结构
    with open(f"{output_prefix}-G.json", 'w') as f:
        json.dump(nx.node_link_data(G, edges="links"), f)

    # 保存节点编号映射
    with open(f"{output_prefix}-id_map.json", 'w') as f:
        json.dump(id_map, f)

    # 保存类别标签
    with open(f"{output_prefix}-class_map.json", 'w') as f:
        json.dump(class_map, f)

    # 保存特征矩阵
    np.save(f"{output_prefix}-feats.npy", feats)

    # 保存节点属性 CSV
    nodes_data = []
    for node in nodes:
        node_type = G.nodes[node].get('type')
        node_data = {
            'node_id': node,
            'feat_domain': int(node_type in ['fqdn', 'apex']),
            'feat_ip': int(node_type == 'ip'),
            'feat_subnet': int(node_type == 'subnet'),
            'label': class_map[node]
        }
        for i, feat in enumerate(features[node]):
            node_data[f'feat_{i}'] = feat
        nodes_data.append(node_data)
    pd.DataFrame(nodes_data).to_csv(f"{output_prefix}-nodes.csv", index=False)

    # 保存边属性 CSV
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

    # 控制台输出统计信息
    hijacked_count = sum(1 for node in domain_nodes if class_map[node] == 1)
    normal_count = sum(1 for node in domain_nodes if class_map[node] == 0)
    print(f"数据转换完成！输出文件前缀：{output_prefix}")
    print(f"节点数量：{len(nodes)}")
    print(f"特征维度：{feature_dim}")
    print(f"域名节点数量：{len(domain_nodes)}")
    print(f"训练集大小：{len(train_nodes)}")
    print(f"验证集大小：{len(val_nodes)}")
    print(f"测试集大小：{len(test_nodes)}")
    print(f"被劫持域名数量：{hijacked_count}")
    print(f"正常域名数量：{normal_count}")


if __name__ == "__main__":
    # 示例入口
    gml_file = "your_graph.gml"
    features_file = "node_features.json"
    output_prefix = "graph_data"
    convert_gml_to_graphsage(gml_file, features_file, output_prefix)
