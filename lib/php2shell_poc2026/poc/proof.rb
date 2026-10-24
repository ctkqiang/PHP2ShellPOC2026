# frozen_string_literal: true

module PHP2ShellPOC2026
  module Poc
    # Reads the local proof file. The command writes /out/p1 on the target;
    # the lab maps that directory back to ./out/p1.
    module Proof
      module_function

      def read(path)
        return "".b unless File.file?(path)

        File.binread(path).strip
      rescue SystemCallError
        "".b
      end
    end
  end
end
