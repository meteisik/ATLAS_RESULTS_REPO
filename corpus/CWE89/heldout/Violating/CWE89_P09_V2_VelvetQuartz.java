import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VelvetQuartz {
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

    public void runVelvetQuartz() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("VELVET_QUARTZ_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VelvetQuartzSink()).queryVelvetQuartz(dataContainer);
    }
}

class CWE89_P09_V2_VelvetQuartzSink {
    public void queryVelvetQuartz(CWE89_P09_V2_VelvetQuartz.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection velvetQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetQuartz");
        Statement velvetQuartzStatement = null;
        ResultSet velvetQuartzRows = null;
        try {
            velvetQuartzStatement = velvetQuartzConnection.createStatement();
            velvetQuartzRows = velvetQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetQuartzRows.getRow());
        } finally {
            if (velvetQuartzRows != null) {
                velvetQuartzRows.close();
            }
            if (velvetQuartzStatement != null) {
                velvetQuartzStatement.close();
            }
            velvetQuartzConnection.close();
        }
    }
}
