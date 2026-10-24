import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetQuartz {

    public static String data;

    public void runVelvetQuartz() throws SQLException {
        data = System.getenv("VELVET_QUARTZ_FILTER");
        (new CWE89_P10_V1_VelvetQuartzSink()).queryVelvetQuartz();
    }
}

class CWE89_P10_V1_VelvetQuartzSink {
    public void queryVelvetQuartz() throws SQLException {
        String data = CWE89_P10_V1_VelvetQuartz.data;
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
