import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_VelvetSignalSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runVelvetSignal() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_VelvetSignalSafeSink()).queryVelvetSignal(dataArray);
    }
}

class CWE89_P08_V2_VelvetSignalSafeSink {
    public void queryVelvetSignal(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
