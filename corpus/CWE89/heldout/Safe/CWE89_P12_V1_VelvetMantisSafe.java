import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetMantisSafe {

    public void runVelvetMantis() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VelvetMantisSafeBase baseObject = new CWE89_P12_V1_VelvetMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetMantisSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetMantisSafeSink extends CWE89_P12_V1_VelvetMantisSafeBase {
    public void action(String data) throws SQLException {
        Connection velvetMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetMantis");
        Statement velvetMantisStatement = null;
        ResultSet velvetMantisRows = null;
        try {
            velvetMantisStatement = velvetMantisConnection.createStatement();
            velvetMantisRows = velvetMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetMantisRows.getRow());
        } finally {
            if (velvetMantisRows != null) {
                velvetMantisRows.close();
            }
            if (velvetMantisStatement != null) {
                velvetMantisStatement.close();
            }
            velvetMantisConnection.close();
        }
    }
}
