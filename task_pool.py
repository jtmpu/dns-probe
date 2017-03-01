#!/usr/bin/env python
import sys
import time
import threading
import Queue

class ResultReporter:
    def __init__(self):
        self.queue = Queue.Queue()

    def report(self, result):
        self.queue.put(result)


class TaskWorker(threading.Thread):
    def __init__(self, identifier, queue, result_reporter, rate):
        threading.Thread.__init__(self)
        self.identifier = identifier
        self.rate = rate
        self.seconds_per_task = 1.0 / self.rate     
        self.terminated = False
        self.queue = queue
        self.result_reporter = result_reporter
    
    def terminate(self):
        # cause locks are for cowards?
        self.terminated = True

    def run(self):
        while not self.terminated:
            task = self.queue.get()
            if task == "shutdown":
                # Fulhacket
                break
            start = time.time()
            result = task[0](*task[1])
            self.result_reporter.report(result)
            elapsed = time.time() - start
            delay = max(self.seconds_per_task - elapsed, 0)
            time.sleep(delay) 

class TaskPool:
    def __init__(self, rate, thread_count):
        self.rate = rate
        self.seconds_per_task = 1.0 / self.rate
        self.thread_count = thread_count
        self.queue = Queue.Queue()
        self.tasks = []
        self.result_reporter = ResultReporter()
        self.threads = []
        for i in range(0, thread_count):
            self.threads.append(TaskWorker(i, self.queue, self.result_reporter, self.rate))

    def add_task(self, func_ptr, *args):
        self.tasks.append((func_ptr, args))

    def cleanup(self):
        # Manual cleanup
        for t in self.threads:
            t.terminate()
            self.queue.put("shutdown")
        for t in self.threads:
            try:
                t.join()
            except:
                continue
    
    def perform_tasks(self):
        for t in self.threads:
            t.start()
        
        task_index = 0
        task_count = len(self.tasks)
        while task_index < task_count:
            # Limit tasks enqueued
            start = time.time()
            self.queue.put(self.tasks[task_index])
            task_index += 1
            elapsed = time.time() - start
            delay = max(self.seconds_per_task - elapsed, 0)
            time.sleep(delay)
        
        # Wait for tasks to complete
        while not self.queue.empty():
            # wait for duration of one job to complete before polling again
            time.sleep(self.seconds_per_task)
            current_size = task_count - self.queue.qsize()

        self.cleanup()  


# 2 per second
#task_count = int(sys.argv[1])
#thread_count = int(sys.argv[2])
#rate = int(sys.argv[3])
#seconds_per_job = 1.0 / rate
#logger = Logger(sys.stdout)
#
#task_pool = TaskPool(thread_count, rate)
#for i in range(0, task_count):
    #task_pool.add_task(lambda x: x + 1, i)
#
#task_pool.perform_tasks()
#
#while not task_pool.result_reporter.queue.empty():
    #print(task_pool.result_reporter.queue.get())
#
#logger.start()
#logger.terminate()
#logger.join()
