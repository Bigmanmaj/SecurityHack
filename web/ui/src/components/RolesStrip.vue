<script setup>
defineProps({ roles: { type: Array, default: () => [] } });
</script>

<template>
  <section class="card">
    <div class="card-head">
      <div>
        <span class="eyebrow">who is involved</span>
        <h3>Six parties, four keys</h3>
      </div>
      <span class="tiny">no private key is ever written, logged or shared</span>
    </div>

    <div class="roles">
      <article v-for="role in roles" :key="role.name" class="role">
        <header>
          <span class="name mono">{{ role.name }}</span>
          <span class="chip" :class="role.key ? 'chip-violet' : 'chip-green'">
            {{ role.key ? "signs" : "no key" }}
          </span>
        </header>
        <p class="tiny">{{ role.does }}</p>
      </article>
    </div>
  </section>
</template>

<style scoped>
.roles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: 10px;
}

.role {
  padding: 12px 13px;
  background: rgba(8, 11, 20, 0.45);
  border: 1px solid var(--border);
  border-radius: 12px;
  transition: border-color 0.15s, transform 0.15s;
}

.role:hover {
  border-color: var(--border-strong);
  transform: translateY(-2px);
}

header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 6px;
}

.name {
  font-weight: 600;
  font-size: 13px;
  color: var(--text);
}
</style>
