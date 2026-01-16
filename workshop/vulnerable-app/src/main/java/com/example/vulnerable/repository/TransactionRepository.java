package com.example.vulnerable.repository;

import com.example.vulnerable.model.Transaction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long> {

    List<Transaction> findByFromUserIdOrToUserId(Long fromUserId, Long toUserId);

    @Query("SELECT t FROM Transaction t WHERE t.fromUserId = ?1 OR t.toUserId = ?1 ORDER BY t.timestamp DESC")
    List<Transaction> findAllByUserId(Long userId);
}
