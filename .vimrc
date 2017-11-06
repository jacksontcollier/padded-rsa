source ~/.vimrc

colo github

let NERDTreeIgnore = ['rsa-dec$', 'rsa-enc$', 'rsa-keygen$', '\.o']

autocmd VimLeave * NERDTreeClose
autocmd VimLeave * mksession!

autocmd StdinReadPre * let s:std_in=1
autocmd VimEnter * if argc() == 0 && !exists("s:std_in") | NERDTree | endif
