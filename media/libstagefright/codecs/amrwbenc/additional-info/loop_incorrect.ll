; ModuleID = 'loop_incorrect.bc'
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"
target triple = "aarch64--linux-android"

; Function Attrs: norecurse nounwind sspstrong uwtable
define void @loop_incorrect(i16* nocapture %exc, i16* nocapture readonly %code, i16 %gain_code, i16 %gain_pit, i32 %i_subfr) #3 {
min.iters.checked:
  %0 = sext i16 %gain_code to i32
  %1 = sext i16 %gain_pit to i32
  %2 = sext i32 %i_subfr to i64
  %3 = sext i32 %i_subfr to i64
  %scevgep = getelementptr i16, i16* %exc, i64 %3
  %4 = add nsw i64 %3, 63
  %scevgep6 = getelementptr i16, i16* %exc, i64 %4
  %scevgep9 = getelementptr i16, i16* %code, i64 63
  %bound0 = icmp ule i16* %scevgep, %scevgep9
  %bound1 = icmp uge i16* %scevgep6, %code
  %memcheck.conflict = and i1 %bound0, %bound1
  br i1 %memcheck.conflict, label %.lr.ph.i.preheader, label %vector.ph

.lr.ph.i.preheader:                               ; preds = %min.iters.checked
  br label %.lr.ph.i

vector.ph:                                        ; preds = %min.iters.checked
  %broadcast.splatinsert11 = insertelement <8 x i32> undef, i32 %0, i32 0
  %broadcast.splat12 = shufflevector <8 x i32> %broadcast.splatinsert11, <8 x i32> undef, <8 x i32> zeroinitializer
  %broadcast.splatinsert16 = insertelement <8 x i32> undef, i32 %1, i32 0
  %broadcast.splat17 = shufflevector <8 x i32> %broadcast.splatinsert16, <8 x i32> undef, <8 x i32> zeroinitializer
  br label %vector.body

vector.body:                                      ; preds = %vector.body, %vector.ph
  %index = phi i64 [ 0, %vector.ph ], [ %index.next, %vector.body ]
  %5 = getelementptr inbounds i16, i16* %code, i64 %index
  %6 = bitcast i16* %5 to <8 x i16>*
  %wide.load = load <8 x i16>, <8 x i16>* %6, align 2
  %7 = sext <8 x i16> %wide.load to <8 x i32>
  %8 = mul nsw <8 x i32> %7, %broadcast.splat12
  %9 = shl <8 x i32> %8, <i32 6, i32 6, i32 6, i32 6, i32 6, i32 6, i32 6, i32 6>
  %10 = add i64 %index, %2
  %11 = getelementptr inbounds i16, i16* %exc, i64 %10
  %12 = bitcast i16* %11 to <8 x i16>*
  %wide.load15 = load <8 x i16>, <8 x i16>* %12, align 2
  %13 = sext <8 x i16> %wide.load15 to <8 x i32>
  %14 = mul nsw <8 x i32> %13, %broadcast.splat17
  %15 = icmp eq <8 x i32> %14, <i32 1073741824, i32 1073741824, i32 1073741824, i32 1073741824, i32 1073741824, i32 1073741824, i32 1073741824, i32 1073741824>
  %16 = shl nsw <8 x i32> %14, <i32 1, i32 1, i32 1, i32 1, i32 1, i32 1, i32 1, i32 1>
  %17 = select <8 x i1> %15, <8 x i32> <i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647>, <8 x i32> %16
  %18 = add nsw <8 x i32> %17, %9
  %19 = xor <8 x i32> %17, %9
  %20 = icmp sgt <8 x i32> %19, <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>
  %21 = xor <8 x i32> %18, %9
  %22 = icmp slt <8 x i32> %21, zeroinitializer
  %23 = and <8 x i1> %20, %22
  %24 = lshr <8 x i32> %8, <i32 25, i32 25, i32 25, i32 25, i32 25, i32 25, i32 25, i32 25>
  %25 = and <8 x i32> %24, <i32 1, i32 1, i32 1, i32 1, i32 1, i32 1, i32 1, i32 1>
  %26 = add nuw <8 x i32> %25, <i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647>
  %27 = select <8 x i1> %23, <8 x i32> %26, <8 x i32> %18
  %28 = icmp slt <8 x i32> %27, <i32 -1073741824, i32 -1073741824, i32 -1073741824, i32 -1073741824, i32 -1073741824, i32 -1073741824, i32 -1073741824, i32 -1073741824>
  %29 = shl <8 x i32> %27, <i32 1, i32 1, i32 1, i32 1, i32 1, i32 1, i32 1, i32 1>
  %30 = select <8 x i1> %28, <8 x i32> <i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648>, <8 x i32> %29
  %31 = icmp sle <8 x i32> %27, <i32 1073741823, i32 1073741823, i32 1073741823, i32 1073741823, i32 1073741823, i32 1073741823, i32 1073741823, i32 1073741823>
  %predphi = select <8 x i1> %31, <8 x i32> %30, <8 x i32> <i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647>
  %32 = add nsw <8 x i32> %predphi, <i32 32768, i32 32768, i32 32768, i32 32768, i32 32768, i32 32768, i32 32768, i32 32768>
  %33 = icmp sgt <8 x i32> %predphi, <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>
  %34 = xor <8 x i32> %32, %predphi
  %35 = icmp slt <8 x i32> %34, zeroinitializer
  %36 = and <8 x i1> %33, %35
  %37 = lshr <8 x i32> %predphi, <i32 31, i32 31, i32 31, i32 31, i32 31, i32 31, i32 31, i32 31>
  %38 = add nuw <8 x i32> %37, <i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647>
  %39 = select <8 x i1> %36, <8 x i32> %38, <8 x i32> %32
  %40 = lshr <8 x i32> %39, <i32 16, i32 16, i32 16, i32 16, i32 16, i32 16, i32 16, i32 16>
  %41 = trunc <8 x i32> %40 to <8 x i16>
  %42 = bitcast i16* %11 to <8 x i16>*
  store <8 x i16> %41, <8 x i16>* %42, align 2
  %index.next = add i64 %index, 8
  %43 = icmp eq i64 %index.next, 64
  br i1 %43, label %middle.block.loopexit18, label %vector.body, !llvm.loop !2

.lr.ph.i:                                         ; preds = %.lr.ph.i.preheader, %L_shl2.exit
  %indvars.iv = phi i64 [ %indvars.iv.next, %L_shl2.exit ], [ 0, %.lr.ph.i.preheader ]
  %44 = getelementptr inbounds i16, i16* %code, i64 %indvars.iv
  %45 = load i16, i16* %44, align 2
  %46 = sext i16 %45 to i32
  %47 = mul nsw i32 %46, %0
  %48 = shl i32 %47, 6
  %49 = add nsw i64 %indvars.iv, %2
  %50 = getelementptr inbounds i16, i16* %exc, i64 %49
  %51 = load i16, i16* %50, align 2
  %52 = sext i16 %51 to i32
  %53 = mul nsw i32 %52, %1
  %54 = icmp eq i32 %53, 1073741824
  %55 = shl nsw i32 %53, 1
  %L_var_out.0.i = select i1 %54, i32 2147483647, i32 %55
  %56 = add nsw i32 %L_var_out.0.i, %48
  %57 = xor i32 %L_var_out.0.i, %48
  %58 = icmp sgt i32 %57, -1
  %59 = xor i32 %56, %48
  %60 = icmp slt i32 %59, 0
  %or.cond.i2 = and i1 %58, %60
  %61 = lshr i32 %47, 25
  %62 = and i32 %61, 1
  %63 = add nuw i32 %62, 2147483647
  %L_var_out.0.i3 = select i1 %or.cond.i2, i32 %63, i32 %56
  %64 = icmp sgt i32 %L_var_out.0.i3, 1073741823
  br i1 %64, label %L_shl2.exit, label %65

; <label>:65                                      ; preds = %.lr.ph.i
  %66 = icmp slt i32 %L_var_out.0.i3, -1073741824
  %67 = shl i32 %L_var_out.0.i3, 1
  %. = select i1 %66, i32 -2147483648, i32 %67
  br label %L_shl2.exit

L_shl2.exit:                                      ; preds = %65, %.lr.ph.i
  %L_var_out.1.i = phi i32 [ 2147483647, %.lr.ph.i ], [ %., %65 ]
  %68 = add nsw i32 %L_var_out.1.i, 32768
  %69 = icmp sgt i32 %L_var_out.1.i, -1
  %70 = xor i32 %68, %L_var_out.1.i
  %71 = icmp slt i32 %70, 0
  %or.cond.i = and i1 %69, %71
  %72 = lshr i32 %L_var_out.1.i, 31
  %73 = add nuw i32 %72, 2147483647
  %L_var_out.0.i1 = select i1 %or.cond.i, i32 %73, i32 %68
  %74 = lshr i32 %L_var_out.0.i1, 16
  %75 = trunc i32 %74 to i16
  store i16 %75, i16* %50, align 2
  %indvars.iv.next = add nuw nsw i64 %indvars.iv, 1
  %exitcond = icmp eq i64 %indvars.iv.next, 64
  br i1 %exitcond, label %middle.block.loopexit, label %.lr.ph.i, !llvm.loop !5

middle.block.loopexit:                            ; preds = %L_shl2.exit
  br label %middle.block

middle.block.loopexit18:                          ; preds = %vector.body
  br label %middle.block

middle.block:                                     ; preds = %middle.block.loopexit18, %middle.block.loopexit
  ret void
}

attributes #0 = { nounwind sspstrong uwtable "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="cortex-a53" "target-features"="+crc,+crypto,+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind }
attributes #2 = { "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="cortex-a53" "target-features"="+crc,+crypto,+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { norecurse nounwind sspstrong uwtable "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="cortex-a53" "target-features"="+crc,+crypto,+neon" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #4 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"PIC Level", i32 2}
!1 = !{!"Android clang version 3.8.256229  (based on LLVM 3.8.256229)"}
!2 = distinct !{!2, !3, !4}
!3 = !{!"llvm.loop.vectorize.width", i32 1}
!4 = !{!"llvm.loop.interleave.count", i32 1}
!5 = distinct !{!5, !3, !4}
!6 = distinct !{!6, !3, !4}
!7 = distinct !{!7, !3, !4}
!8 = distinct !{!8, !3, !4}
!9 = distinct !{!9, !3}
!10 = distinct !{!10, !3, !4}
!11 = distinct !{!11, !3, !4}
!12 = distinct !{!12, !3, !4}
