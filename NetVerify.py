indices = []
            while True: # 入力選択ループ
                try:
                    choice = input(f"番号 (all/0.../b): ").lower().strip()
                    if not choice:
                        sys.stdout.write(CLEAR_LINE)
                        continue
                    if choice == 'b': break
                    
                    indices = range(len(hosts)) if choice == 'all' else [int(i.strip()) for i in choice.split(',') if i.strip().isdigit() and int(i.strip()) < len(hosts)]
                    if indices: break
                    else: sys.stdout.write(CLEAR_LINE)
                except (KeyboardInterrupt, EOFError):
                    choice = 'b'
                    break
                except: sys.stdout.write(CLEAR_LINE)

            if choice == 'b': 
                # 画面クリアを廃止
                show_mode_menu()
                break
