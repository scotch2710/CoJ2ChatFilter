# CoJ2ChatFilter - build online

Come ottenere la dll compilata senza installare nulla:

1. Crea un account su github.com (gratis)
2. Crea un **nuovo repository pubblico** (es. "CoJ2ChatFilter") - New -> Repository -> name -> Public -> Create
3. Carica TUTTI i file di questa cartella nella radice del repository
   (Add file -> Upload files, trascina tutto, Commit)
4. Vai su tab **Actions**: la build parte da sola. Se e' disattivata,
   abilita i workflow e premi "Run workflow"
5. Quando finisce (segno verde, ~2 minuti), clicca sulla run ->
   sezione **Artifacts** -> scarica "CoJ2ChatFilter-x86"
6. Nello zip trovi CoJ2ChatFilter.dll + chatfilter.ini pronte all'uso

Per ricompilare dopo modifiche a main.cpp: modifica il file su GitHub,
la build riparte automaticamente.
