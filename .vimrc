source ~/.vimrc

colo github

let NERDTreeIgnore = ['rsa-dec$', 'rsa-enc$', 'rsa-keygen$', '\.o']

autocmd VimLeave * NERDTreeClose
autocmd VimLeave * mksession!

autocmd VimEnter * NERDTree
