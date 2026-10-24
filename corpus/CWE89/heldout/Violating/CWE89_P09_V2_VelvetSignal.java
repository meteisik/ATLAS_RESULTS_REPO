import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VelvetSignal {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String containerOne;
    }

    public void runVelvetSignal() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("VELVET_SIGNAL_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VelvetSignalSink()).queryVelvetSignal(dataContainer);
    }
}

class CWE89_P09_V2_VelvetSignalSink {
    public void queryVelvetSignal(CWE89_P09_V2_VelvetSignal.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection velvetSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSignal");
        Statement velvetSignalStatement = null;
        ResultSet velvetSignalRows = null;
        try {
            velvetSignalStatement = velvetSignalConnection.createStatement();
            velvetSignalRows = velvetSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetSignalRows.getRow());
        } finally {
            if (velvetSignalRows != null) {
                velvetSignalRows.close();
            }
            if (velvetSignalStatement != null) {
                velvetSignalStatement.close();
            }
            velvetSignalConnection.close();
        }
    }
}
