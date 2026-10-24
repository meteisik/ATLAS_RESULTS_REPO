import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetCipher {

    public void runVelvetCipher() throws SQLException {
        String data;
        data = System.getenv("VELVET_CIPHER_FILTER");
        CWE89_P12_V1_VelvetCipherBase baseObject = new CWE89_P12_V1_VelvetCipherSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetCipherBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetCipherSink extends CWE89_P12_V1_VelvetCipherBase {
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
