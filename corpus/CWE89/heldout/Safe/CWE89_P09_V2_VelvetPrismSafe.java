import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VelvetPrismSafe {
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

    public void runVelvetPrism() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VelvetPrismSafeSink()).queryVelvetPrism(dataContainer);
    }
}

class CWE89_P09_V2_VelvetPrismSafeSink {
    public void queryVelvetPrism(CWE89_P09_V2_VelvetPrismSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection velvetPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetPrism");
        Statement velvetPrismStatement = null;
        ResultSet velvetPrismRows = null;
        try {
            velvetPrismStatement = velvetPrismConnection.createStatement();
            velvetPrismRows = velvetPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetPrismRows.getRow());
        } finally {
            if (velvetPrismRows != null) {
                velvetPrismRows.close();
            }
            if (velvetPrismStatement != null) {
                velvetPrismStatement.close();
            }
            velvetPrismConnection.close();
        }
    }
}
