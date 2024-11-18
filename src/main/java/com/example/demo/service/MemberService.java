package com.example.demo.service;

import com.example.demo.dto.JoinDTO;
import com.example.demo.entity.Member;
import com.example.demo.repository.MemberRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class MemberService {
    private final MemberRepository memberRepository;

    private final PasswordEncoder passwordEncoder;

    public MemberService(MemberRepository memberRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.memberRepository = memberRepository;
        this.passwordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDTO joinDTO) {
        final String username = joinDTO.getUsername();
        final String password = joinDTO.getPassword();

        boolean isExist = memberRepository.existsByUsername(username);

        if (isExist) {
            return;
        }

        Member member = new Member();
        member.setUsername(username);
        member.setPassword(passwordEncoder.encode(password));
        member.setRole("ROLE_ADMIN");

        memberRepository.save(member);
    }
}
