.PHONY: all clean

all:
	@for dir in part1b part2; do \
		$(MAKE) -C $$dir; \
	done

clean:
	@for dir in part1b part2; do \
		$(MAKE) -C $$dir clean; \
	done

