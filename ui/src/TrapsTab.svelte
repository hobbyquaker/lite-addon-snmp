<script lang="ts">
    // The notifications: the targets and the rules (shown once the agent sends notifications).
    import type {NoticesStore} from 'occulite-ui/notices';

    import type {Config} from './model.js';

    let {config, notices, onchanged}: {config: Config; notices: NoticesStore; onchanged: (c: Config) => void} = $props();
</script>

<section class="snmp-section" data-notices={notices.visible.length} data-onchanged={typeof onchanged}>{config.traps.targets.length}</section>
