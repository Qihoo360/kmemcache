kmemcache
=========

kmemcache is a high-performance, distributed memory object caching system, generic in nature,
but intended for use in speeding up dynamic web applications by alleviating database load.

kmemcache is derived from memcached-v1.4.15, exactly it is a linux kernel memcached,
and aims at quicker response and higher performance.

Current Limitations
-------------------
kmemcache has now implemented all most major features of memcached, including the complete binary
and text protocols, based on tcp, udp and unix domain communication protocols, slab allocation 
dynamically rebalanced, hash table expansion and so on.

The programming interface remains consistent with memcached. Clients using memcached can easily 
connected to kmemcache, without modification. You could also easily add the kmemcache server to
your cluster of memcached servers.

The following are some features that have not been implemented yet:  
* SASL

Environment
-----------
x86_32/x86_64	
kernel: [2.6.32, 3.2]	
other versions have not been tested

Building, Running & Testing
---------------------------
1) Clone kmemcache from github

	[jgli@linux]$ git clone https://github.com/jgli/kmemcache.git

2) Compiling kmemcache

	[jgli@linux]$ cd kmemcache
	[jgli@linux]$ make

3) Running kmemcache

3.1 Change user to root

	[jgli@linux]$ su root
	Password:

3.2 Insert kernel module and start server

	[root@linux]# insmod kmod/kmemcache.ko
	[root@linux]# user/umemcached -h
	[root@linux]# user/umemcached -p 11213

4) Stopping kmemcache

	[root@linux]# rmmod kmemcache

5) Testing kmemcache	

5.1 Case 1, using libmemcached

	[root@linux]# apt-get install libmemcached
	[root@linux]# memcapable -h localhost -p 11213
	[root@linux]# memslap --servers=localhost:11213

5.2 Case 2, using testapp

	[root@linux]# insmod kmod/kmctest.ko
	[root@linux]# ./test/testapp

5.3 Case 3, using perl scripts

	[root@linux]# ./t/00-startup.t

5.4 More cases refer to memcached

Contributing
------------
Want to contribute? You are so welcome! Any reporting bugs, feedback, and pulling requests are encouraged!

Website
-------
Official memcached: http://www.memcached.org/	
Test tools: http://libmemcached.org/libMemcached.html	
Something about kmemcache from my blog: http://blog.sina.com.cn/u/3289939872
