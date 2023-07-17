all: boot_info.py Parser.py
	pip install -r requirements.txt
	dos2unix boot_info.py
	dos2unix Parser.py
	cat boot_info.py Parser.py > boot_info_temp.py
	mv boot_info_temp.py boot_info
	chmod u+x boot_info

boot_info: boot_info.py
	dos2unix boot_info.py
	cp boot_info.py boot_info
	chmod +x boot_info

clean:
	rm -f *~
	rm -f main

.PHONY: all clean