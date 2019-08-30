package pullrequest

import (
	"testing"
)

func Test_pullRequestMessageValidator_validateTitle(t *testing.T) {
	type args struct {
		pr *pullRequest
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "should not include invalid characters '�'",
			args: args{
				pr: &pullRequest{
					Title: "base: normal title �",
				},
			},
			wantErr: true,
		},
		{
			name: "should not include Chinese colon",
			args: args{
				pr: &pullRequest{
					Title: "base： normal title",
				},
			},
			wantErr: true,
		},
		{
			name: "should end with (#xxx)",
			args: args{
				pr: &pullRequest{
					Title: "base: normal title (#100)",
				},
			},
			wantErr: false,
		},
		{
			name: "should end with words",
			args: args{
				pr: &pullRequest{
					Title: "base: normal title",
				},
			},
			wantErr: false,
		},
		{
			name: "should end with chinese characters",
			args: args{
				pr: &pullRequest{
					Title: "base: 汉字标题",
				},
			},
			wantErr: false,
		},
		{
			name: "should end with digits",
			args: args{
				pr: &pullRequest{
					Title: "base: 999",
				},
			},
			wantErr: false,
		},
		{
			name: "should not include continuous whitespaces",
			args: args{
				pr: &pullRequest{
					Title: "base:  normal title",
				},
			},
			wantErr: true,
		},
		{
			name: "should have a revert scope",
			args: args{
				pr: &pullRequest{
					Title: "revert: base: normal title",
				},
			},
			wantErr: false,
		},
		{
			name: "should have a scope",
			args: args{
				pr: &pullRequest{
					Title: "normal title",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validator.validateTitle(tt.args.pr); (err != nil) != tt.wantErr {
				t.Errorf("pullRequestMessageValidator.validateTitle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_pullRequestMessageValidator_validateBody(t *testing.T) {
	type args struct {
		pr *pullRequest
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "should not include invalid characters '�'",
			args: args{
				pr: &pullRequest{
					Body: "normal body�",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validator.validateBody(tt.args.pr); (err != nil) != tt.wantErr {
				t.Errorf("pullRequestMessageValidator.validateBody() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
