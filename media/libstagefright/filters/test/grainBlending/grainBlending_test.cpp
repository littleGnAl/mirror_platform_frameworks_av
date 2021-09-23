/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 /*****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
*/
/*!
 **************************************************************************/
/*!
 **************************************************************************
 * \file grainBlending_test.cpp
 *
 * \brief
 *    Contains sample application to demonstrate use of grain blending APIs
 *
 * \date
 *    14/09/2021
 *
 * \author  NS
 **************************************************************************
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include "grainBlending.h"

using namespace android;

#define ENABLE_VIDEO_WRITE 1

#define MAX_QUEUE_NAME_SIZE         64
#define MAX_STRING_LENGTH           4096
#define MAX_LOG_LENGTH              MAX_STRING_LENGTH

#define UNIT_APP_MAX_LINE_LEN       1024
#define UNIT_APP_MAX_NUM_PARAM      30
#define UNIT_APP_MAX_PARAM_LEN      1024
#define MAX_FILE_NAME_STR_SIZE      1024

/*---------------------------------------------------------------------------*/
/*                           Structure Definitions                           */
/*---------------------------------------------------------------------------*/

/* Film Grain Synthesizer application context */
typedef struct fgs_app_params_t
{
  /* Frame num from FGC params are applicable*/
  uint32_t startFrameNum;
  /* Frame num till FGC params are applicable*/
  uint32_t endFrameNum;
  /* Total number of frames to be processed */
  uint32_t numFrames;
  /* Configuration file */
  char initParamsCfgFile[MAX_LOG_LENGTH];
  /* Input YUV file name */
  char inputFileName[MAX_LOG_LENGTH];
  /* Output YUV file name */
  char outputFile[MAX_LOG_LENGTH];
  /* Input width */
  uint32_t frameWidth;
  /* Input height */
  uint32_t frameHeight;
  /* Input bit depth */
  uint8_t bitDepth;
  /* Input chroma format */
  uint8_t chromaFmt;
  /* Number of threads*/
  int32_t numThreads;
  /* Set processor architecture*/
  uint32_t processorArch;
}fgs_app_params;

char g_param[UNIT_APP_MAX_NUM_PARAM][UNIT_APP_MAX_PARAM_LEN];

int32_t is_comment(char *line)
{
    /* If line starts with '#', it's a comment line */
    if ('#' == line[0])
        return 1;
    else
        return 0;
}

int32_t is_blank(char *line)
{
  int32_t i = 0;
  /* Check for occurrence of any int8_tacters other than ' ' and '\t' */
  for (i = 0; ; i++)
  {
    if (' ' != line[i] && '\t' != line[i])
      break;
  }

  /* Found int8_tacter other than space */
  if ('\r' != line[i] && '\n' != line[i] &&
    (int8_t)EOF != line[i] && '\0' != line[i])
    return 0;
  else
    return 1;/* Found int8_tacter was '\n' or EOF */
}


int32_t get_next_parameter(char *line, uint32_t line_length,
    uint32_t *position_in_line,
    char *data, uint32_t data_length)
{
  uint32_t i = 0;
  int32_t flag = 0;

  if (*position_in_line > line_length)
  {
    return 0;
  }

/* Skip preceding space int8_tacters until any other character is found    */
/* from given search position                                            */
  while (' ' == line[*position_in_line] ||
    '\t' == line[*position_in_line] ||
    '\n' == line[*position_in_line] ||
    (char)EOF == line[*position_in_line] ||
    '\0' == line[*position_in_line] ||
    '=' == line[*position_in_line] ||
    '(' == line[*position_in_line] ||
    ')' == line[*position_in_line] ||
    ':' == line[*position_in_line])
  {
    /* If Found was '\n' or EOF, there was no other character other than */
    /* space or the first character was the '\n' or EOF from the given   */
    /* search position                                                   */
    if ('\n' == line[*position_in_line] ||
        '\0' == line[*position_in_line] ||
        (char)EOF == line[*position_in_line])
    {
      data[0] = '\0';
      return 0;
    }
    (*position_in_line)++;
    if (*position_in_line > line_length)
    {
      return 0;
    }
  }
  flag = 0;
  /* Store the substring character in the output buffer until delimiters */
  /* found                                                                */
  while (flag || (
      '=' != line[*position_in_line] &&
      '(' != line[*position_in_line] &&
      ')' != line[*position_in_line] &&
      (char)EOF != line[*position_in_line] &&
      '\n' != line[*position_in_line] &&
      '\0' != line[*position_in_line] &&
      ' ' != line[*position_in_line] &&
      ':' != line[*position_in_line])
      )
  {
    /* If first single quote (') is found then skip checking for other
     * delimiters until second single quote is found */
    if ('\'' == line[*position_in_line])
    {
      flag = !flag;
      (*position_in_line)++;
      continue;
    }
    data[i++] = line[(*position_in_line)++];
    if (*position_in_line > line_length || i > data_length)
      return 0;
  }

  data[i] = '\0';   /* Suffix with NULL character */
  return 1;
}

int32_t get_next_parameter_allow_spaces(
    char *line, uint32_t line_length,
    uint32_t *position_in_line,
    char *data, uint32_t data_length)
{
  uint32_t i = 0;
  if (*position_in_line > line_length)
  {
    return 0;
  }

  /* Skip preceding space characters until any other character is found    */
  /* from given search position                                            */
  while (' ' == line[*position_in_line] ||
      '\t' == line[*position_in_line] ||
      '\n' == line[*position_in_line] ||
      (char)EOF == line[*position_in_line] ||
      '\0' == line[*position_in_line] ||
      '=' == line[*position_in_line] ||
      '(' == line[*position_in_line] ||
      ')' == line[*position_in_line] ||
      ':' == line[*position_in_line])
  {
    /* If Found was '\n' or EOF, there was no other character other than */
    /* space or the first int8_tacter was the '\n' or EOF from the given   */
    /* search position                                                   */
    if ('\n' == line[*position_in_line] ||
        '\0' == line[*position_in_line] ||
        (char)EOF == line[*position_in_line])
    {
      data[0] = '\0';
      return 0;
    }

    (*position_in_line)++;
    if (*position_in_line > line_length)
        return 0;
  }

  /* Store the substring charatacter in the output buffer until demlimiters */
  /* found                                                                */
  while (
      '=' != line[*position_in_line] &&
      '(' != line[*position_in_line] &&
      ')' != line[*position_in_line] &&
      (char)EOF != line[*position_in_line] &&
      '\n' != line[*position_in_line] &&
      '\0' != line[*position_in_line] )
  {
    data[i++] = line[(*position_in_line)++];

    if (*position_in_line > line_length || i > data_length)
      return 0;
  }

  /* If the last int8_tacter happen to be '=', then remove any spaces at the */
  /* end of the params                                                     */
  if ('=' == line[*position_in_line])
  {
    --i;
    /* Get back to previous int8_tacter */
    while ((' ' == data[i]) || ('\t' == data[i]))
    {
      data[i] = '\0';
      --i;
    }
    i += 1;/* Set the int8_tacter to next position */
  }
  data[i] = '\0'; /* Suffix with NULL character */
  return 1;
}

void get_all_params_of_line(char   *line,
    uint32_t    line_length,
    char   param[UNIT_APP_MAX_NUM_PARAM][UNIT_APP_MAX_PARAM_LEN],
    uint32_t    *num_params,
    uint32_t    allow_spaces_for_params)
{
  int32_t  status;
  uint32_t position_in_line = 0,param_number=0;

  /* Extract all the parameters into the parameter array */
  for (param_number = 0; ; param_number++)
  {
    if (0 == allow_spaces_for_params)
    {
      status = get_next_parameter(line,
          line_length,
          &position_in_line,
          param[param_number],
          UNIT_APP_MAX_PARAM_LEN);

      if ((0 == status) || (0 == param[param_number]))
        break;
    }
    else
    {
      status = get_next_parameter_allow_spaces(line,
          line_length,
          &position_in_line,
          param[param_number],
          UNIT_APP_MAX_PARAM_LEN);

      if ((0 == status) || (0 == param[param_number]))
          break;
    }
  }
  *num_params = param_number;
}

int32_t set_input_params(FILE *cur_fp, fgs_app_params* psAppParams)
{
  char line[UNIT_APP_MAX_LINE_LEN] = { 0 };
  uint32_t    num_params = 0;

  for (;;)
  {
    if (0 != fgets(line, UNIT_APP_MAX_LINE_LEN, cur_fp))
    {
      /* Remove the newline / carriage return character */
      {
        uint32_t line_len = (uint32_t)strlen(line);

        if ('\r' == line[line_len - 1] || '\n' == line[line_len - 1])
          line[line_len - 1] = '\0';
      }

      /* Ignore blank lines and comments */
      if (1 == is_comment(line) || 1 == is_blank(line))
      {
        continue;
      }

      /* Break when the end tag is found */
      if (NULL != strstr(line, "INPUT_PARAMS_END"))
      {
        break;
      }

      /* Get all the params present in the line */
      get_all_params_of_line(line, UNIT_APP_MAX_LINE_LEN,
        g_param, &num_params, 1);

      /* Assumed that values are always in name,value pairs */
      if (num_params < 2)
        return -1;

      if (0 == strcmp(g_param[0], "input_yuv_file_name"))
      {
        strncpy(psAppParams->inputFileName,
            g_param[1], MAX_FILE_NAME_STR_SIZE);
        psAppParams->inputFileName[MAX_FILE_NAME_STR_SIZE - 1] = '\0';
        printf("inputFileName : %s\n", psAppParams->inputFileName);
      }
      else if (0 == strcmp(g_param[0], "output_yuv_file_name"))
      {
        strncpy(psAppParams->outputFile,
            g_param[1], MAX_FILE_NAME_STR_SIZE);
        psAppParams->outputFile[MAX_FILE_NAME_STR_SIZE - 1] = '\0';
        printf("outputFile : %s\n", psAppParams->outputFile);

      }
      else if (0 == strcmp(g_param[0], "num_frames"))
      {
        psAppParams->numFrames = atoi(g_param[1]);
        printf("numFrames : %d\n", psAppParams->numFrames);
      }
      else if (0 == strcmp(g_param[0], "width"))
      {
        psAppParams->frameWidth = atoi(g_param[1]);
        printf("frameWidth : %d\n", psAppParams->frameWidth);
      }
      else if (0 == strcmp(g_param[0], "height"))
      {
        psAppParams->frameHeight = atoi(g_param[1]);
        printf("frameHeight : %d\n", psAppParams->frameHeight);
      }
      else if (0 == strcmp(g_param[0], "bit_depth"))
      {
        psAppParams->bitDepth = atoi(g_param[1]);
        printf("bitDepth : %d\n", psAppParams->bitDepth);
      }
      else if (0 == strcmp(g_param[0], "chroma_format"))
      {
        psAppParams->chromaFmt = atoi(g_param[1]);
        printf("chromaFormat : %d\n", psAppParams->chromaFmt);
      }
      else if (0 == strcmp(g_param[0], "num_threads"))
      {
        psAppParams->numThreads = atoi(g_param[1]);
        printf("numThreads : %d\n", psAppParams->numThreads);
      }
      else if (0 == strcmp(g_param[0], "ARCH"))
      {
        if ((strcmp(g_param[1], "ARCH_ARM_GENERIC")) == 0)
            psAppParams->processorArch = ARCH_ARM_GENERIC;
        else if ((strcmp(g_param[1], "ARCH_ARMV8_INTRINSICS")) == 0)
            psAppParams->processorArch = ARCH_ARMV8_INTRINSICS;
        else if ((strcmp(g_param[1], "ARCH_X86_GENERIC")) == 0)
            psAppParams->processorArch = ARCH_X86_GENERIC;
        else if ((strcmp(g_param[1], "ARCH_X86_AVX_INTRINSICS")) == 0)
            psAppParams->processorArch = ARCH_X86_AVX_INTRINSICS;
        else {
            printf("\nInvalid Arch. Setting it to ARCH_ARM_GENERIC\n");
            psAppParams->processorArch = ARCH_ARM_GENERIC;
        }

        printf("processorArch : %d\n", psAppParams->processorArch);
      }
      else
      {
        printf("Invalid param name [%s] being passed to %s[%d]\n",
            g_param[0], __FUNCTION__, __LINE__);
        return FAILURE_RET;
      }
    }
  }
  return SUCCESS_RET;
}

int32_t set_fgc_prf_params(FILE *cur_fp, fgs_app_params* psAppParams,
                            FilmGrainCharacteristicsStruct *psFgcParameters)
{
  char   line[UNIT_APP_MAX_LINE_LEN] = { 0 };
  uint32_t    num_params = 0;
  char *token;
  int32_t i = 0, j = 0, k = 0, v = 0;
  int32_t max_num_of_values = 0;
  int32_t num_intensity_itvls = 0;

  for (;;)
  {
    if (0 != fgets(line, UNIT_APP_MAX_LINE_LEN, cur_fp))
    {
      /* Remove the newline / carriage return int8_tacter */
      {
        uint32_t line_len = (uint32_t)strlen(line);
        if ('\r' == line[line_len - 1] || '\n' == line[line_len - 1])
            line[line_len - 1] = '\0';
      }

      /* Ignore blank lines and comments */
      if (1 == is_comment(line) || 1 == is_blank(line))
      {
        continue;
      }
      /* Break when the end tag is found */
      if (NULL != strstr(line, "FGC_PARAMS_PROFILE_END"))
      {
        psFgcParameters->filmGrainCharacteristicsRepetitionPeriod = 0;
        printf("\n film_grain_int8_tacteristics_repetition_period : %d\n",
                    psFgcParameters->filmGrainCharacteristicsRepetitionPeriod);
        printf("\n------------------ FGS End ----------------- \n\n ");
        break;
      }

      /* Get all the params present in the line */
      get_all_params_of_line(line, UNIT_APP_MAX_LINE_LEN,
          g_param, &num_params, 1);

      /* Assumed that values are always in name,value pairs */
      if (num_params < 2)
        return -1;

      if (0 == strcmp(g_param[0], "start_frame_num"))
      {
        psAppParams->startFrameNum = atoi(g_param[1]);
        printf("startFrameNum : %d\n", psAppParams->startFrameNum);
      }
      else if (0 == strcmp(g_param[0], "end_frame_num"))
      {
        psAppParams->endFrameNum = atoi(g_param[1]);
        printf("endFrameNum : %d\n", psAppParams->endFrameNum);
      }
      else if (0 == strcmp(g_param[0], "film_grain_characteristics_cancel_flag"))
      {
        psFgcParameters->filmGrainCharacteristicsCancelFlag = atoi(g_param[1]);
        printf("film_grain_charactacteristics_cancel_flag : %d\n",
                        psFgcParameters->filmGrainCharacteristicsCancelFlag);
      }
      else if (0 == strcmp(g_param[0], "film_grain_model_id"))
      {
        psFgcParameters->filmGrainModelId = atoi(g_param[1]);
        printf("film_grain_model_id : %d\n", psFgcParameters->filmGrainModelId);
      }
      else if (0 == strcmp(g_param[0], "separate_colour_description_present_flag"))
      {
        psFgcParameters->separateColourDescriptionPresentFlag = atoi(g_param[1]);
        printf("separate_colour_description_present_flag : %d\n",
                    psFgcParameters->separateColourDescriptionPresentFlag);
      }
      else if (0 == strcmp(g_param[0], "blending_mode_id"))
      {
        psFgcParameters->blendingModeId = atoi(g_param[1]);
        printf("blending_mode_id : %d\n", psFgcParameters->blendingModeId);
      }
      else if (0 == strcmp(g_param[0], "log2_scale_factor"))
      {
        psFgcParameters->log2ScaleFactor = atoi(g_param[1]);
        printf("log2_scale_factor : %d\n", psFgcParameters->log2ScaleFactor);
      }
      else if(0 == strcmp(g_param[0], "blockSize"))
      {
        psFgcParameters->blockSize = atoi(g_param[1]);
        printf("blockSize : %d\n", psFgcParameters->blockSize);
      }

      else if (0 == strcmp(g_param[0], "disableFGSforChroma"))
      {
        psFgcParameters->disableFGSforChroma = atoi(g_param[1]);
        printf("disableFGSforChroma : %d\n", psFgcParameters->disableFGSforChroma);
      }
      else if (0 == strcmp(g_param[0], "comp_model_present_flag"))
      {
        i = 0;
        token = strtok(g_param[1],",");
        while (token != NULL)
        {
          if (i < FGS_MAX_NUM_COMP)
          {
            psFgcParameters->compModelPresentFlag[i] = atoi(token);
            i++;
            token = strtok(NULL, ",");
          }
          else
          {
            printf("Invalid number of values [%d] being passed to parameter: [%s]\n",
                i, g_param[0]);
            return FAILURE_RET;
          }
        }
        if (i < FGS_MAX_NUM_COMP)
        {
          printf("Invalid number of values [%d] being passed to parameter: [%s]\n",
              i, g_param[0]);
          return FAILURE_RET;
        }
        printf("comp_model_present_flag : ");
        for (i = 0; i < FGS_MAX_NUM_COMP; i++)
          printf("%d ", psFgcParameters->compModelPresentFlag[i]);
        printf("\n");
      }
      else if (0 == strcmp(g_param[0], "num_intensity_intervals_minus1"))
      {
        i = 0;
        token = strtok(g_param[1], ",");
        while (token != NULL)
        {
          if (i < FGS_MAX_NUM_COMP)
          {
            psFgcParameters->numIntensityIntervalsMinus1[i] = atoi(token);
            i++;
            token = strtok(NULL, ",");
          }
          else
          {
            printf("Invalid number of values [%d] being passed to parameter: [%s]\n",
                i, g_param[0]);
            return FAILURE_RET;
          }
        }
        if (i < FGS_MAX_NUM_COMP)
        {
          printf("Invalid number of values [%d] being passed to parameter: [%s]\n",
              i, g_param[0]);
          return FAILURE_RET;
        }

        printf("num_intensity_intervals_minus1 : ");
        for (i = 0; i < FGS_MAX_NUM_COMP; i++)
          printf("%d ", psFgcParameters->numIntensityIntervalsMinus1[i]);
        printf("\n");
      }
      else if (0 == strcmp(g_param[0], "num_model_values_minus1"))
      {
        i = 0;
        token = strtok(g_param[1], ",");
        while (token != NULL)
        {
          if (i < FGS_MAX_NUM_COMP)
          {
            psFgcParameters->numModelValuesMinus1[i] = atoi(token);
            i++;
            token = strtok(NULL, ",");
          }
          else
          {
            printf("Invalid number of values [%d] being passed to parameter: [%s]\n",
                i, g_param[0]);
            return FAILURE_RET;
          }
        }
        if (i < FGS_MAX_NUM_COMP)
        {
          printf("Invalid number of values [%d] being passed to parameter: [%s]\n",
              i, g_param[0]);
          return FAILURE_RET;
        }
        printf("num_model_values_minus1 : ");
        for (i = 0; i < FGS_MAX_NUM_COMP; i++)
          printf("%d ", psFgcParameters->numModelValuesMinus1[i]);
        printf("\n");
      }
      else if (0 == strcmp(g_param[0], "intensity_interval_lower_bound"))
      {
        i = 0;
        max_num_of_values = 0;
        num_intensity_itvls = 0;
        token = strtok(g_param[1], ",");

        for (i = 0; i < FGS_MAX_NUM_COMP; i++)
        {
          max_num_of_values += (psFgcParameters->compModelPresentFlag[i] *
                                    (psFgcParameters->numIntensityIntervalsMinus1[i] + 1));
        }
        printf("intensity_interval_lower_bound : ");
        i = 0;
        for (j = 0; j < FGS_MAX_NUM_COMP; j++)
        {
          num_intensity_itvls = (1 + psFgcParameters->numIntensityIntervalsMinus1[j])*
                                    psFgcParameters->compModelPresentFlag[j];
          for (k = 0; k < (num_intensity_itvls); k++)
          {
            if (token == NULL)
            {
              printf("Invalid number of values [%d] being passed to parameter: [%s]\n",
                  i, g_param[0]);
              return FAILURE_RET;
            }
            else
            {
              psFgcParameters->intensityIntervalLowerBound[j][k] = atoi(token);
              printf("%d ", psFgcParameters->intensityIntervalLowerBound[j][k]);
              token = strtok(NULL, ",");
              i++;
            }
          }
        }
        printf("\n");
      }
      else if (0 == strcmp(g_param[0], "intensity_interval_upper_bound"))
      {
        i = 0;
        max_num_of_values = 0;
        num_intensity_itvls = 0;
        token = strtok(g_param[1], ",");
        for (i = 0; i < FGS_MAX_NUM_COMP; i++)
        {
          max_num_of_values += psFgcParameters->compModelPresentFlag[i] *
                                    (1 + psFgcParameters->numIntensityIntervalsMinus1[i]);
        }
        printf("intensity_interval_upper_bound : ");
        i = 0;
        for (j = 0; j < FGS_MAX_NUM_COMP; j++)
        {
          num_intensity_itvls = (1 + psFgcParameters->numIntensityIntervalsMinus1[j])*
                                    psFgcParameters->compModelPresentFlag[j];
          for (k = 0; k < (num_intensity_itvls); k++)
          {
            if (token == NULL)
            {
              printf("Invalid number of values [%d] being passed to parameter: [%s]\n",
                  i, g_param[0]);
              return FAILURE_RET;
            }
            else
            {
              psFgcParameters->intensityIntervalUpperBound[j][k] = atoi(token);
              printf("%d ", psFgcParameters->intensityIntervalUpperBound[j][k]);
              token = strtok(NULL, ",");
              i++;
            }
          }
        }
        printf("\n");
      }
      else if (0 == strcmp(g_param[0], "comp_model_value"))
      {
        int max_num_of_values = 0;
        int num_intensity_itvls = 0;
        int num_comp_model_values = 0;

        for (i = 0; i < FGS_MAX_NUM_COMP; i++)
        {
          max_num_of_values += psFgcParameters->compModelPresentFlag[i] *
                                (1 + psFgcParameters->numIntensityIntervalsMinus1[i]) *
                                    (1 + psFgcParameters->numModelValuesMinus1[i]);
        }
        printf("comp_model_value : ");
        i = 0; j = 0;
        token = strtok(g_param[1], ",");

        if (i < max_num_of_values)
        {
        for (j = 0; j < FGS_MAX_NUM_COMP; j++)
       {
          num_intensity_itvls = (1 + psFgcParameters->numIntensityIntervalsMinus1[j])*
                                    psFgcParameters->compModelPresentFlag[j];
          for (k = 0; k < (num_intensity_itvls); k++)
          {
          num_comp_model_values = (1 + psFgcParameters->numModelValuesMinus1[j]) *
              psFgcParameters->compModelPresentFlag[j];
          for (v = 0; v < (num_comp_model_values); v++)
          {
              if (token == NULL)
              {
              printf("Invalid number of values [%d] being passed to parameter: [%s]\n",
                  i, g_param[0]);
              return FAILURE_RET;
              }
              else
              {
              psFgcParameters->compModelValue[j][k][v] = atoi(token);
              printf("%d ", psFgcParameters->compModelValue[j][k][v]);
              token = strtok(NULL, ",");
              i++;
              }
            }
          }
        }
        }
        else
        {
        printf("Invalid number of values [>%d] being passed to parameter: [%s]\n",
            i, g_param[0]);
        return FAILURE_RET;
        }
      }
      else
      {
        printf("Invalid param name [%s] being passed to %s[%d]\n",
            g_param[0], __FUNCTION__, __LINE__);
        return FAILURE_RET;
      }
    }
  }
  return SUCCESS_RET;
}

int32_t fgs_parse_config_params(fgs_app_params *psAppParams,
               FILE *cur_fp,FilmGrainCharacteristicsStruct *psFgcParameters)
{
  char   line[UNIT_APP_MAX_LINE_LEN];
  int32_t  status = 0;
  memset(psFgcParameters,0,sizeof(FilmGrainCharacteristicsStruct));
  /* Read till next set of FGC params are encountered */
  for (;;)
  {
    if (0 != fgets(line, UNIT_APP_MAX_LINE_LEN, cur_fp))
    {
      /* Remove the newline / carriage return int8_tacter */
      {
        size_t line_len = strlen(line);
        if ('\r' == line[line_len - 1] || '\n' == line[line_len - 1])
            line[line_len - 1] = '\0';
      }
      /* Ignore blank lines and comments */
      if (1 == is_comment(line) || 1 == is_blank(line))
        continue;

      /* Parse Input Params */
      else if (NULL != strstr(line, "INPUT_PARAMS_START"))
      {
        status = set_input_params(cur_fp, psAppParams);
        if (status != SUCCESS_RET)
        {
          printf("One or more params not set in set_input_params\n");
          return FAILURE_RET;
        }
        return SUCCESS_RET;
      }
      /* Parse the FGC Params Profile */
      else if (NULL != strstr(line, "FGC_PARAMS_PROFILE_START"))
      {
        printf("\n-------------- FGS Start -----------------\n\n ");
        status = set_fgc_prf_params(cur_fp, psAppParams, psFgcParameters);
        if (status != SUCCESS_RET)
        {
          printf("One or more params not set in set_fgc_prf_params\n");
          return FAILURE_RET;
        }
        return SUCCESS_RET;
      }
      else
      {
        printf("Unknown stray parameter in configuration file: %s\n",line);
      }
    }
    else
    {
      break;
    }
  }
  return SUCCESS_RET;
}

/* Main function */
int main(int argc, char *argv[])
{
  int32_t status = 0,bytesRead;
  int32_t sizeInBytes = 0;
  uint32_t frameNum = 0;
  FILE *cur_fp = NULL;
  FILE *outputFile = NULL;
  uint8_t* pdecPelFrm;
  FILE *inputFile;/* Input YUV file pointer */
  void *psFgsHandle;
  fgs_app_params *psFgsAppParams = (fgs_app_params*)malloc(sizeof(fgs_app_params));
  GrainCharacteristicApi fgcCTx ;//= { 0 };
  int8_t height_shift, width_shift;
  if (NULL == psFgsAppParams)
  {
    printf("[Error] Failed to allocate memory\n");
    return FAILURE_RET;
  }
  if (2 != argc) {
    printf("[ERROR] Invalid number of arguments, %d provided\n", argc);
    printf("Example: ./fgs_app.out fgs_config.txt\n");
    return FAILURE_RET;
  }

  strcpy(psFgsAppParams->initParamsCfgFile, argv[1]);
  /* Parse and validate init params from file */
  cur_fp = fopen(psFgsAppParams->initParamsCfgFile, "r");
  if (!cur_fp)
  {
    printf("Failed to open configuration file: %s\n",
        psFgsAppParams->initParamsCfgFile);
    return FAILURE_RET;
  }

  /* Parse Input Params from Config File */
  status = fgs_parse_config_params(psFgsAppParams, cur_fp, &(fgcCTx.fgcParameters));
  if (SUCCESS_RET != status)
  {
    printf("Failed to parse configuration file: %s\n",
                psFgsAppParams->initParamsCfgFile);
    fclose(cur_fp);
    return FAILURE_RET;
  }
  fgcCTx.width = psFgsAppParams->frameWidth;
  fgcCTx.height = psFgsAppParams->frameHeight;
  fgcCTx.bitDepth = psFgsAppParams->bitDepth;
  fgcCTx.chromaFormat = psFgsAppParams->chromaFmt;
  //fgcCTx.numThreads = psFgsAppParams->numThreads;

  if (1 == fgcCTx.chromaFormat) /* 420 */
  {
    sizeInBytes = (psFgsAppParams->frameWidth * psFgsAppParams->frameHeight * 3) >> 1;
    height_shift = 1;
    width_shift = 1;
  }
  else if (2 == fgcCTx.chromaFormat) /* 422 */
  {
    sizeInBytes = (psFgsAppParams->frameWidth * psFgsAppParams->frameHeight) << 1;
    height_shift = 0;
    width_shift = 1;
  }
  else if (3 == fgcCTx.chromaFormat) /* 444 */
  {
    sizeInBytes = (psFgsAppParams->frameWidth * psFgsAppParams->frameHeight * 3);
    height_shift = 0;
    width_shift = 0;
  }
  else if (0 == fgcCTx.chromaFormat) /* Monochrome */
  {
    sizeInBytes = (psFgsAppParams->frameWidth * psFgsAppParams->frameHeight);
  }
  else
  {
    assert(0);
  }

  sizeInBytes = sizeInBytes * ((fgcCTx.bitDepth+7)/8);

  /*Init call to generate handlew with data base*/
  FGSInitParams initParams;
  initParams.maxWidth = psFgsAppParams->frameWidth;
  initParams.maxHeight = psFgsAppParams->frameHeight;
  initParams.maxbitDepth = psFgsAppParams->bitDepth;
  initParams.numThreads = psFgsAppParams->numThreads;
  initParams.processorArch = psFgsAppParams->processorArch;

  /*Init call to generate handlew with data base*/
  psFgsHandle = fgs_create(&initParams);

  /* Open input and output files */
  inputFile = fopen(psFgsAppParams->inputFileName, "rb");
  outputFile = fopen(psFgsAppParams->outputFile, "wb+");

  if (!inputFile)
  {
    printf("Failed to open input yuv %s\n",psFgsAppParams->inputFileName);
    return FAILURE_RET;
  }

  if (!outputFile)
  {
    printf("Failed to open output yuv %s\n",psFgsAppParams->outputFile);
    return FAILURE_RET;
  }
  /* Allocate memory for frame level buf */
  pdecPelFrm = (uint8_t*)malloc(sizeof(uint8_t)*sizeInBytes);

  /* Start configuration file parsing, Exit on reaching the end of file */
  for (;;)
  {
    if (getc(cur_fp) == EOF)
    {
      while ((frameNum < psFgsAppParams->numFrames))
      {
        bytesRead = fread(pdecPelFrm, sizeInBytes, sizeof(uint8_t), inputFile);
        if (!bytesRead)
        {
          printf("Reached end of input file\n");
          break;
        }
        frameNum++;
#if ENABLE_VIDEO_WRITE
        fwrite(pdecPelFrm, sizeInBytes, sizeof(uint8_t), outputFile);
#endif
      }
      break;
    }
    else
    {
      status = fgs_parse_config_params(psFgsAppParams, cur_fp, &(fgcCTx.fgcParameters));
      if (SUCCESS_RET != status)
      {
        printf("Failed to parse configuration file: %s\n",
            psFgsAppParams->initParamsCfgFile);
        fclose(cur_fp);
        return FAILURE_RET;
      }

      if (psFgsAppParams->startFrameNum >= frameNum)
      {
        if (psFgsAppParams->startFrameNum > frameNum)
        {
          while ((frameNum < psFgsAppParams->startFrameNum) && (frameNum < psFgsAppParams->numFrames))
          {
           bytesRead = fread(pdecPelFrm, sizeInBytes, sizeof(uint8_t), inputFile);
             if (!bytesRead)
             {
               printf("Reached end of input file\n");
               break;
             }
            frameNum++;
#if ENABLE_VIDEO_WRITE
            fwrite(pdecPelFrm, sizeInBytes, sizeof(uint8_t), outputFile);
#endif
          }
        }
        int16_t buf_offset_val = 1;
        if(fgcCTx.bitDepth > 8)
        {
          buf_offset_val = 1;
        }
        /* Interface b/w App and Lib START */
        while ((frameNum < psFgsAppParams->endFrameNum) && (frameNum < psFgsAppParams->numFrames))
        {
          fgcCTx.poc = frameNum % 256;
          fgcCTx.idrPicId = 0;
          bytesRead = fread(pdecPelFrm, sizeInBytes, sizeof(uint8_t), inputFile);
          if (!bytesRead)
          {
            printf("Reached end of input file\n");
            break;
          }
          fgcCTx.decBufY = pdecPelFrm;
          if(fgcCTx.bitDepth > 8)
          {
            fgcCTx.decBufU = (void *)((uint16_t *)pdecPelFrm +
                                        psFgsAppParams->frameWidth * psFgsAppParams->frameHeight);
            fgcCTx.decBufV = (void *)((uint16_t *)fgcCTx.decBufU +
                                        (psFgsAppParams->frameWidth >> width_shift) *
                                                (psFgsAppParams->frameHeight>>height_shift));
          }
          else
          {
            fgcCTx.decBufU = (void *)((uint8_t *)pdecPelFrm + psFgsAppParams->frameWidth *
                                                                    psFgsAppParams->frameHeight);
            fgcCTx.decBufV = (void *)((uint8_t *)fgcCTx.decBufU +
                                                    (psFgsAppParams->frameWidth >> width_shift) *
                                                    (psFgsAppParams->frameHeight >> height_shift));
          }
          fgcCTx.strideY = psFgsAppParams->frameWidth;
          fgcCTx.strideU = (psFgsAppParams->frameWidth >> width_shift);
          fgcCTx.strideV = (psFgsAppParams->frameWidth >> width_shift);


          /* Function call to Film Grain Synthesizer */
          fgcCTx.errorCode = fgs_process(fgcCTx,psFgsHandle);
          if(FGS_SUCCESS != fgcCTx.errorCode)
          {
            printf(" \n Grain synthesis in not performed. Error code: 0x%x ",fgcCTx.errorCode);
          }
          frameNum++;
#if ENABLE_VIDEO_WRITE
          fwrite(pdecPelFrm, sizeInBytes, sizeof(uint8_t), outputFile);
#endif
        }/* End of interface between App and Lib */
      }
      else
      {
        printf("Invalid value specified for startFrameNum in configuration file: %s\n",
            psFgsAppParams->initParamsCfgFile);
        fclose(cur_fp);
        fclose(inputFile);
        return FAILURE_RET;
      }
    }
  }
  /* Close configuration file */
  fclose(cur_fp);
  fclose(inputFile);
  fclose(outputFile);
  fgs_delete(psFgsHandle);
  if (NULL != psFgsAppParams)
  {
    free(pdecPelFrm);
    free(psFgsAppParams);
  }
  //print_all_times();
  printf("Done executing Film Grain Synthesizer\n");
  return SUCCESS_RET;
}
