ARGC=$#
if [ $ARGC -le 5 ]; then
    exit 0;
fi

REKALL=$1
DOMAIN=$2
FUNC=$3
NO_OF_ARGS=$4
ARGS=$5

kernel_injector -r $REKALL -d $DOMAIN -f $FUNC -n $NO_OF_ARGS -a $ARGS
