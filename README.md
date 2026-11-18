# tryhackme

Plugin do Claude Code com a skill **`security-scan`**: uma análise de segurança do próprio ambiente, somente leitura, que percorre as etapas de um atacante automatizado e reporta, a cada etapa, o que foi encontrado, o que precisa ser corrigido e o que pode ser explorado, com prioridade P0, P1 ou P2.

- [Documentação da skill](docs/README.md)
- [Os scripts, um por um](docs/scripts.md)
- [A skill](skills/security-scan/SKILL.md)

Para carregar o plugin a partir desta pasta:

```bash
claude --plugin-dir /caminho/para/este/repositorio
```

Para rodar os testes dos scripts:

```bash
python3 -m unittest discover -s tests
```

Estado: em construção. As etapas, as regras e a graduação estão escritas, e os scripts da etapa 0 (escopo e arquitetura) estão implementados e testados. Os playbooks por tecnologia e os scripts das etapas finais ainda são esboços. Veja "Estado atual" na documentação.
