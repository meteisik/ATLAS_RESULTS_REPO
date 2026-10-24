import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VelvetSundialSafe {
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

    public void runVelvetSundial() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VelvetSundialSafeSink()).queryVelvetSundial(dataContainer);
    }
}

class CWE89_P09_V2_VelvetSundialSafeSink {
    public void queryVelvetSundial(CWE89_P09_V2_VelvetSundialSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection velvetSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSundial");
        Statement velvetSundialStatement = null;
        ResultSet velvetSundialRows = null;
        try {
            velvetSundialStatement = velvetSundialConnection.createStatement();
            velvetSundialRows = velvetSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetSundialRows.getRow());
        } finally {
            if (velvetSundialRows != null) {
                velvetSundialRows.close();
            }
            if (velvetSundialStatement != null) {
                velvetSundialStatement.close();
            }
            velvetSundialConnection.close();
        }
    }
}
