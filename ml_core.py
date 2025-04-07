import random
import itertools
from collections import defaultdict
from metrics import calculate_metrics

class QLearningAgent:
    def __init__(self,
                 attack_classes=None,
                 pps_levels=None,
                 threads_levels=None,
                 power_levels=None,
                 duration_levels=None,
                 max_combo=2,
                 alpha=0.1, gamma=0.9,
                 epsilon_start=0.9, epsilon_end=0.1,
                 epsilon_decay=0.98):
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon_start
        self.epsilon_start = epsilon_start
        self.epsilon_end = epsilon_end
        self.epsilon_decay = epsilon_decay
        self.attack_classes = attack_classes or []
        self.pps_levels = pps_levels or [1, 2, 3]
        self.threads_levels = threads_levels or [1, 2]
        self.power_levels = power_levels or [1]
        self.duration_levels = duration_levels or [1, 2]
        self.max_combo = max_combo
        self.actions = self._generate_action_space()
        self.Q = defaultdict(lambda: defaultdict(float))
        self.history = []

    def _generate_action_space(self):
        single_actions = []
        for cls in self.attack_classes:
            atk_obj = cls()
            for pps in self.pps_levels:
                for thr in self.threads_levels:
                    for pw in self.power_levels:
                        for dur in self.duration_levels:
                            single_actions.append((atk_obj, pps, thr, pw, dur))
        combo_actions = []
        for size in range(1, self.max_combo + 1):
            for subset in itertools.combinations(single_actions, size):
                combo_actions.append(subset)
        return combo_actions

    def select_action(self, state):
        if random.random() < self.epsilon:
            return random.choice(self.actions)
        qvals = self.Q[state]
        if not qvals:
            return random.choice(self.actions)
        best_act = max(qvals, key=qvals.get)
        return best_act

    def update_q(self, state, action, reward, next_state):
        current_q = self.Q[state][action]
        next_q_vals = self.Q[next_state]
        max_next = max(next_q_vals.values()) if next_q_vals else 0.0
        new_q = current_q + self.alpha * (reward + self.gamma * max_next - current_q)
        self.Q[state][action] = new_q

    def decay_epsilon(self):
        if self.epsilon > self.epsilon_end:
            self.epsilon *= self.epsilon_decay
            if self.epsilon < self.epsilon_end:
                self.epsilon = self.epsilon_end

    def record_outcome(self, pred_label, true_label):
        self.history.append((pred_label, true_label))

    def compute_metrics(self):
        return calculate_metrics(self.history)

    def get_best_action(self, state):
        qvals = self.Q[state]
        if not qvals:
            return None
        return max(qvals, key=qvals.get)

    def reset_history(self):
        self.history = []
