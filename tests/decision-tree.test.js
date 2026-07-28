import { describe, it, expect } from 'vitest';

// ═══════════════════════════════════════════════════════════
// 从 worker.js 中提取的决策树路由逻辑（第1487-1524行）
// ═══════════════════════════════════════════════════════════

/**
 * 决策树路由：根据当前节点和信号判断下一个节点
 * @param {Array} treeNodes - 活跃的决策树节点列表
 * @param {string} currentNodeId - 当前节点 ID
 * @param {Object} signals - 前端回传的充分性信号 { hasFact, hasEmotion, hasNeed, emotion }
 * @param {number} round - 当前对话轮次
 * @returns {Object|null} 路由结果 { nextNodeId, nodeType, prompt }，无匹配返回 null
 */
function routeDecisionTree(treeNodes, currentNodeId, signals, round) {
  if (!treeNodes || treeNodes.length === 0 || !currentNodeId) {
    return null; // 无决策树数据或未指定当前节点，回退到旧逻辑
  }

  const currentNode = treeNodes.find(n => n.node_id === currentNodeId);
  if (!currentNode) {
    return null; // 当前节点在树中找不到，回退到旧逻辑
  }

  const sig = signals || { hasFact: false, hasEmotion: false, hasNeed: false };
  const currentRound = round || 1;

  let nextNodeId = null;

  if (currentNode.condition_type === 'has_fact') {
    nextNodeId = sig.hasFact ? currentNode.next_node_sufficient : currentNode.next_node_insufficient;
  } else if (currentNode.condition_type === 'has_emotion') {
    nextNodeId = sig.hasEmotion ? currentNode.next_node_sufficient : currentNode.next_node_insufficient;
  } else if (currentNode.condition_type === 'has_need') {
    nextNodeId = sig.hasNeed ? currentNode.next_node_sufficient : currentNode.next_node_insufficient;
  } else if (currentNode.condition_type === 'round_count') {
    nextNodeId = currentRound >= parseInt(currentNode.condition_value) ? currentNode.next_node_sufficient : currentNode.next_node_insufficient;
  } else {
    // 未知条件类型，默认走 sufficient 路径
    nextNodeId = currentNode.next_node_sufficient;
  }

  return {
    nextNodeId,
    nodeType: currentNode.node_type,
    currentNodeId: currentNode.node_id,
    prompt: currentNode.prompt_template,
  };
}

// ═══════════════════════════════════════════════════════════
// 构造测试用的决策树
// ═══════════════════════════════════════════════════════════

function buildTestTree() {
  return [
    {
      id: 1,
      node_id: 'start',
      parent_id: null,
      node_type: 'opening',
      condition_type: 'has_fact',
      condition_value: '',
      prompt_template: '请告诉我发生了什么？',
      next_node_sufficient: 'deep_fact',
      next_node_insufficient: 'gather_fact',
      description: '开场节点',
      is_active: 1,
      sort_order: 0,
    },
    {
      id: 2,
      node_id: 'gather_fact',
      parent_id: 'start',
      node_type: 'fact_gathering',
      condition_type: 'has_emotion',
      condition_value: '',
      prompt_template: '你现在的感受是怎样的？',
      next_node_sufficient: 'emotion_explore',
      next_node_insufficient: 'continue_fact',
      description: '收集事实节点',
      is_active: 1,
      sort_order: 1,
    },
    {
      id: 3,
      node_id: 'deep_fact',
      parent_id: 'start',
      node_type: 'deep_fact',
      condition_type: 'round_count',
      condition_value: '3',
      prompt_template: '你已经说了很多，让我们深入一下',
      next_node_sufficient: 'closure',
      next_node_insufficient: 'deep_fact_continue',
      description: '深度事实节点',
      is_active: 1,
      sort_order: 2,
    },
    {
      id: 4,
      node_id: 'emotion_explore',
      parent_id: 'gather_fact',
      node_type: 'emotion_exploration',
      condition_type: 'has_need',
      condition_value: '',
      prompt_template: '你真正需要的是什么？',
      next_node_sufficient: 'need_address',
      next_node_insufficient: 'emotion_deep',
      description: '情绪探索节点',
      is_active: 1,
      sort_order: 3,
    },
    {
      id: 5,
      node_id: 'unknown_condition',
      parent_id: null,
      node_type: 'test',
      condition_type: 'custom_type',
      condition_value: '',
      prompt_template: '未知条件测试',
      next_node_sufficient: 'fallback_path',
      next_node_insufficient: 'other_path',
      description: '未知条件类型节点',
      is_active: 1,
      sort_order: 4,
    },
  ];
}

// ═══════════════════════════════════════════════════════════
// 测试用例
// ═══════════════════════════════════════════════════════════

describe('决策树路由逻辑', () => {
  const tree = buildTestTree();

  describe('has_fact 条件判断', () => {
    it('hasFact 为 true 时走 sufficient 路径', () => {
      const result = routeDecisionTree(tree, 'start', { hasFact: true, hasEmotion: false, hasNeed: false }, 1);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('deep_fact');
      expect(result.nodeType).toBe('opening');
    });

    it('hasFact 为 false 时走 insufficient 路径', () => {
      const result = routeDecisionTree(tree, 'start', { hasFact: false, hasEmotion: false, hasNeed: false }, 1);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('gather_fact');
    });

    it('hasFact 默认 false 走 insufficient 路径', () => {
      const result = routeDecisionTree(tree, 'start', {}, 1);
      expect(result.nextNodeId).toBe('gather_fact');
    });
  });

  describe('has_emotion 条件判断', () => {
    it('hasEmotion 为 true 时走 sufficient 路径', () => {
      const result = routeDecisionTree(tree, 'gather_fact', { hasFact: true, hasEmotion: true, hasNeed: false }, 1);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('emotion_explore');
    });

    it('hasEmotion 为 false 时走 insufficient 路径', () => {
      const result = routeDecisionTree(tree, 'gather_fact', { hasFact: true, hasEmotion: false, hasNeed: false }, 1);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('continue_fact');
    });
  });

  describe('round_count 条件判断', () => {
    it('轮次 >= 条件值时走 sufficient 路径', () => {
      const result = routeDecisionTree(tree, 'deep_fact', { hasFact: true }, 3);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('closure');
    });

    it('轮次 > 条件值时走 sufficient 路径', () => {
      const result = routeDecisionTree(tree, 'deep_fact', { hasFact: true }, 5);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('closure');
    });

    it('轮次 < 条件值时走 insufficient 路径', () => {
      const result = routeDecisionTree(tree, 'deep_fact', { hasFact: true }, 1);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('deep_fact_continue');
    });

    it('轮次为 0 时走 insufficient 路径', () => {
      const result = routeDecisionTree(tree, 'deep_fact', { hasFact: true }, 0);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('deep_fact_continue');
    });
  });

  describe('has_need 条件判断', () => {
    it('hasNeed 为 true 时走 sufficient 路径', () => {
      const result = routeDecisionTree(tree, 'emotion_explore', { hasFact: true, hasEmotion: true, hasNeed: true }, 2);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('need_address');
    });

    it('hasNeed 为 false 时走 insufficient 路径', () => {
      const result = routeDecisionTree(tree, 'emotion_explore', { hasFact: true, hasEmotion: true, hasNeed: false }, 2);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('emotion_deep');
    });
  });

  describe('无决策树数据时回退到旧逻辑', () => {
    it('空节点列表返回 null', () => {
      const result = routeDecisionTree([], 'start', { hasFact: true }, 1);
      expect(result).toBeNull();
    });

    it('null 节点列表返回 null', () => {
      const result = routeDecisionTree(null, 'start', { hasFact: true }, 1);
      expect(result).toBeNull();
    });

    it('undefined 节点列表返回 null', () => {
      const result = routeDecisionTree(undefined, 'start', { hasFact: true }, 1);
      expect(result).toBeNull();
    });

    it('无 currentNodeId 返回 null', () => {
      const result = routeDecisionTree(tree, null, { hasFact: true }, 1);
      expect(result).toBeNull();
    });

    it('currentNodeId 在树中找不到返回 null', () => {
      const result = routeDecisionTree(tree, 'nonexistent_node', { hasFact: true }, 1);
      expect(result).toBeNull();
    });
  });

  describe('未知条件类型', () => {
    it('未知 condition_type 默认走 sufficient 路径', () => {
      const result = routeDecisionTree(tree, 'unknown_condition', { hasFact: false }, 1);
      expect(result).not.toBeNull();
      expect(result.nextNodeId).toBe('fallback_path');
    });
  });

  describe('路由结果结构', () => {
    it('返回结果包含正确的结构字段', () => {
      const result = routeDecisionTree(tree, 'start', { hasFact: true }, 1);
      expect(result).toHaveProperty('nextNodeId');
      expect(result).toHaveProperty('nodeType');
      expect(result).toHaveProperty('currentNodeId');
      expect(result).toHaveProperty('prompt');
    });
  });
});
