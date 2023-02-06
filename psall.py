from typing import Optional

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist, psaux


class PsAll(plugins.PluginInterface):
    """
    List processes with all relevant information like arguments and
    environment variables
    """

    _get_command_line_args = psaux.PsAux._get_command_line_args

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="userOnly",
                description="Only show the user processes ",
                default=False,
                optional=True,
            ),
        ]

    def _get_command_line_env(
        self, task: interfaces.objects.ObjectInterface
    ) -> Optional[dict]:
        """Return the environment variables of a specific task as dictonary

        Arguments:
        task -- a specific process
        """
        if task.mm == 0:
            return None

        if not (ps_layer := task.add_process_layer()):
            return renderers.UnreadableValue()

        proc_layer = self.context.layers[ps_layer]

        env_size = task.mm.env_end - task.mm.env_start

        try:
            env = proc_layer.read(task.mm.env_start, env_size)
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue()

        decoded_env = env.decode().split("\x00")

        # Todo: Make this for loop more readable
        env = {}
        for env_var in decoded_env:
            if env_var.find("=") != -1:
                splitted_env = env_var.split("=")
                env[splitted_env[0]] = "".join(splitted_env[1:])

        return env

    def _generator(self, tasks, userOnly: bool):
        """Yield all the tasks with their relevant information

        Arguments:
        tasks -- list of processes
        userOnly -- only show user processes
        """
        for task in tasks:
            pid = task.pid

            if not (ppid := task.parent.pid):
                ppid = 0

            name = utility.array_to_string(task.comm)

            args = self._get_command_line_args(task, name)

            env = self._get_command_line_env(task)

            if env:
                logname = env.get("LOGNAME")

                env_str = "\n----------\nENV:\n"
                for key, val in env.items():
                    env_str += f"- {key}={val}\n"
            else:
                if userOnly:
                    continue
                else:
                    logname = ""
                    env_str = ""

            yield (
                0,
                (
                    f"{pid=}",
                    f"{ppid=}",
                    f"{logname=}",
                    f"{name=}",
                    f"\n{args=}",
                    env_str,
                ),
            )

    def run(self):
        filterLogname = self.config.get("filterLogname")

        return renderers.TreeGrid(
            [
                ("PID", str),
                ("PPID", str),
                ("LOGNAME", str),
                ("COMM", str),
                ("ARGS", str),
                ("ENV", str),
            ],
            self._generator(
                pslist.PsList.list_tasks(self.context, self.config["kernel"]),
                userOnly=filterLogname,
            ),
        )
