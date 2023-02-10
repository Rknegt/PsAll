from typing import Optional

from volatility3.framework import exceptions, interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist, psaux


KERNEL_UID32_T_SIZE = 2


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
                description="Only show the user processes",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="showEnv",
                description="Show environment variables",
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

        """ Cast the environment to a dictonary. """
        env = {}
        for env_var in decoded_env:
            if "=" in env_var:
                key, value = env_var.split("=", 1)
                env[key] = value

        return env

    def _generator(self, tasks, userOnly: bool, showEnv: bool):
        """Yield all the tasks with their relevant information

        Arguments:
        tasks -- list of processes
        userOnly -- only show user processes
        """
        vm_linux = self.context.modules[self.config["kernel"]]
        default_symbol = vm_linux.symbol_table_name + constants.BANG

        for task in tasks:
            pid = task.pid

            if not (ppid := task.parent.pid):
                ppid = 0

            name = utility.array_to_string(task.comm)

            args = self._get_command_line_args(task, name)

            env = self._get_command_line_env(task)

            """ Create the cred object because it is necessary for reading the UID. """
            cred = self.context.object(
                default_symbol + "cred",
                offset=task.cred,
                layer_name=vm_linux.layer_name,
            )

            """Read the UID from the task_struct in bytes because we can't access it through objects. """
            uid = int.from_bytes(
                self._context.layers[vm_linux.layer_name].read(
                    cred.uid.vol.offset, KERNEL_UID32_T_SIZE
                ),
                "little",
            )

            """Read the LOGINUID from the task_struct in bytes because we can't access it through objects. """
            loginuid = int.from_bytes(
                self._context.layers[vm_linux.layer_name].read(
                    task.loginuid.vol.offset, KERNEL_UID32_T_SIZE
                ),
                "little",
            )

            """ Only yield environment variables if the showEnv is True.
            Skip all kernel threads (kernel threads don't have environment variables),
            if userOnly is True. """
            if showEnv:
                if env:
                    env_str = "\n----------\nENV:\n"
                    for key, val in env.items():
                        env_str += f"- {key}={val}\n"
                elif userOnly:
                    continue
                else:
                    env_str = ""
                yield (0, (pid, ppid, loginuid, uid, name, args, env_str))
            else:
                if not env and userOnly:
                    continue
                else:
                    yield (0, (pid, ppid, loginuid, uid, name, args))

    def run(self):
        filterLogname = self.config.get("filterLogname")
        showEnv = self.config.get("showEnv")

        columns = [
            ("PID", int),
            ("PPID", int),
            ("LOGINUID", int),
            ("UID", int),
            ("COMM", str),
            ("ARGS", str),
        ]

        if showEnv:
            columns.append(("ENV", str))

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_tasks(self.context, self.config["kernel"]),
                userOnly=filterLogname,
                showEnv=showEnv,
            ),
        )
