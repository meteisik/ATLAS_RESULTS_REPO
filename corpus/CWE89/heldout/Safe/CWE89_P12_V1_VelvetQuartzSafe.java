import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetQuartzSafe {

    public void runVelvetQuartz() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VelvetQuartzSafeBase baseObject = new CWE89_P12_V1_VelvetQuartzSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetQuartzSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetQuartzSafeSink extends CWE89_P12_V1_VelvetQuartzSafeBase {
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
