import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetCipherSafe {

    public void runVelvetCipher() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VelvetCipherSafeBase baseObject = new CWE89_P12_V1_VelvetCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetCipherSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetCipherSafeSink extends CWE89_P12_V1_VelvetCipherSafeBase {
    public void action(String data) throws SQLException {
        Connection velvetCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCipher");
        Statement velvetCipherStatement = null;
        ResultSet velvetCipherRows = null;
        try {
            velvetCipherStatement = velvetCipherConnection.createStatement();
            velvetCipherRows = velvetCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetCipherRows.getRow());
        } finally {
            if (velvetCipherRows != null) {
                velvetCipherRows.close();
            }
            if (velvetCipherStatement != null) {
                velvetCipherStatement.close();
            }
            velvetCipherConnection.close();
        }
    }
}
