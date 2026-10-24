import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetQuartz {

    public void runVelvetQuartz() throws SQLException {
        String data;
        data = System.getenv("VELVET_QUARTZ_FILTER");
        CWE89_P12_V1_VelvetQuartzBase baseObject = new CWE89_P12_V1_VelvetQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetQuartzBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetQuartzSink extends CWE89_P12_V1_VelvetQuartzBase {
    public void action(String data) throws SQLException {
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
