package com.auth0.samples.authapi.springbootauthupdated.task;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/tasks")
public class TaskController {

    private TaskRepository taskRepository;

    public TaskController(TaskRepository taskRepository) {
        this.taskRepository = taskRepository;
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public void addTask(@RequestBody Task task) {
        taskRepository.save(task);
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
//    @Secured("ROLE_ADMIN")
    public List<Task> getTasks() {
        return taskRepository.findAll();
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public void editTask(@PathVariable long id, @RequestBody Task task) {
        Task existingTask = taskRepository.findById(id).get();
        Assert.notNull(existingTask, "Task not found");
        existingTask.setDescription(task.getDescription());
        taskRepository.save(existingTask);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public void deleteTask(@PathVariable long id) {
        Task taskToDel = taskRepository.findById(id).get();
        taskRepository.delete(taskToDel);
    }
}