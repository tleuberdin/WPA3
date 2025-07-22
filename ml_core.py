# ml_core.py

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
        self.epsilon_end = epsilon_end
        self.epsilon_decay = epsilon_decay

        self.attack_classes = attack_classes or []
        self.pps_levels = pps_levels or [1,2,3]
        self.threads_levels = threads_levels or [1,2]
        self.power_levels = power_levels or [1]
        self.duration_levels = duration_levels or [1,2]
        self.max_combo = max_combo

        self.actions = self._generate_action_space()
        self.Q = defaultdict(lambda: defaultdict(float))
        self.history = []

        self.success_history = []
        self.current_context = None

    def _generate_action_space(self):
        singles = []
        for cls in self.attack_classes:
            obj = cls()
            for pps,thr,pw,dur in itertools.product(
                    self.pps_levels,
                    self.threads_levels,
                    self.power_levels,
                    self.duration_levels):
                singles.append((obj,pps,thr,pw,dur))
        combos = []
        for r in range(1, self.max_combo+1):
            combos += itertools.combinations(singles, r)
        return combos

    def select_action(self, state):
        if random.random() < self.epsilon:
            return random.choice(self.actions)
        qv = self.Q[state]
        return random.choice(self.actions) if not qv else max(qv, key=qv.get)

    def update_q(self, state, action, reward, next_state):
        old = self.Q[state][action]
        nxt = max(self.Q[next_state].values()) if self.Q[next_state] else 0.0
        self.Q[state][action] = old + self.alpha*(reward + self.gamma*nxt - old)

    def decay_epsilon(self):
        if self.epsilon > self.epsilon_end:
            self.epsilon *= self.epsilon_decay
            if self.epsilon < self.epsilon_end:
                self.epsilon = self.epsilon_end

    def record_outcome(self, pred_label, true_label):
        self.history.append((pred_label, true_label))
        if pred_label==1 and true_label==1 and self.current_context:
            self.success_history.append(self.current_context)

    def compute_metrics(self):
        return calculate_metrics(self.history)

    def get_best_action(self, state):
        qv = self.Q[state]
        return None if not qv else max(qv, key=qv.get)
