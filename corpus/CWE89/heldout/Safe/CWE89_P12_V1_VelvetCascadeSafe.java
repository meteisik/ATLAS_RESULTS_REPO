import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetCascadeSafe {

    public void runVelvetCascade() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VelvetCascadeSafeBase baseObject = new CWE89_P12_V1_VelvetCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetCascadeSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetCascadeSafeSink extends CWE89_P12_V1_VelvetCascadeSafeBase {
    public void action(String data) throws SQLException {
        Connection velvetCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCascade");
        Statement velvetCascadeStatement = null;
        ResultSet velvetCascadeRows = null;
        try {
            velvetCascadeStatement = velvetCascadeConnection.createStatement();
            velvetCascadeRows = velvetCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetCascadeRows.getRow());
        } finally {
            if (velvetCascadeRows != null) {
                velvetCascadeRows.close();
            }
            if (velvetCascadeStatement != null) {
                velvetCascadeStatement.close();
            }
            velvetCascadeConnection.close();
        }
    }
}
