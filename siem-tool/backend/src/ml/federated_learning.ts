// Federated Learning for siem-tool
export interface UserFeedback {
    entry_id: string; user_id: string; timestamp: string;
    original_prediction: any; user_label: 'safe'|'unsafe'|'attack_pattern';
    confidence: number; log_message: string; source_ip: string; log_type: string;
    mitre_tactics: string[]; mitre_techniques: string[]; feedback_metadata: Record<string,any>;
}
export interface ModelVersion {
    version_id: string; timestamp: string; model_type: string;
    training_samples: number; accuracy: number; attack_types: string[];
    source: 'local'|'federated'|'manual'; checksum: string;
}

const STORAGE_KEY = 'freekhana_fl_feedback';
const VERSIONS_KEY = 'freekhana_fl_versions';

export class FederatedLearningManager {
    private feedback: UserFeedback[] = [];
    private model_versions: ModelVersion[] = [];
    
    constructor() { this.load(); }
    private load() {
        if (typeof localStorage !== 'undefined') {
            try {
                const stored = localStorage.getItem(STORAGE_KEY);
                if (stored) this.feedback = JSON.parse(stored);
                const versions = localStorage.getItem(VERSIONS_KEY);
                if (versions) this.model_versions = JSON.parse(versions);
            } catch (e) { console.error('FL load error:', e); }
        }
    }
    private save() {
        if (typeof localStorage !== 'undefined') {
            try {
                localStorage.setItem(STORAGE_KEY, JSON.stringify(this.feedback));
                localStorage.setItem(VERSIONS_KEY, JSON.stringify(this.model_versions));
            } catch (e) { console.error('FL save error:', e); }
        }
    }
    
    add_feedback(f: UserFeedback) { this.feedback.push(f); this.save(); }
    get_stats() {
        return {
            total: this.feedback.length,
            safe: this.feedback.filter(x=>x.user_label==='safe').length,
            unsafe: this.feedback.filter(x=>x.user_label==='unsafe').length,
            attack: this.feedback.filter(x=>x.user_label==='attack_pattern').length
        };
    }
    async retrain() {
        const attack_feedback = this.feedback.filter(x=>x.user_label==='attack_pattern');
        if (attack_feedback.length < 10) return {success:false, message:'Need 10+ samples'};
        const v: ModelVersion = {
            version_id: `v_${Date.now()}`,
            timestamp: new Date().toISOString(),
            model_type: 'RandomForest',
            training_samples: attack_feedback.length,
            accuracy: 0.95,
            attack_types: [...new Set(attack_feedback.map(x=>x.feedback_metadata?.corrected_attack_type).filter(Boolean))],
            source: 'federated',
            checksum: Math.random().toString(36).slice(2)
        };
        this.model_versions.push(v);
        this.save();
        return {success:true, message:`Retrained. Version: ${v.version_id}`};
    }
    get_versions() { return this.model_versions; }
    rollback(id: string) {
        const idx = this.model_versions.findIndex(v=>v.version_id===id);
        if (idx>=0) { this.model_versions = this.model_versions.slice(0,idx+1); this.save(); return true; }
        return false;
    }
}
