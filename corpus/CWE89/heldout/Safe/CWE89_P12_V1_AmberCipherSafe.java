import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberCipherSafe {

    public void runAmberCipher() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_AmberCipherSafeBase baseObject = new CWE89_P12_V1_AmberCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberCipherSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberCipherSafeSink extends CWE89_P12_V1_AmberCipherSafeBase {
    public void action(String data) throws SQLException {
        Connection amberCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCipher");
        Statement amberCipherStatement = null;
        ResultSet amberCipherRows = null;
        try {
            amberCipherStatement = amberCipherConnection.createStatement();
            amberCipherRows = amberCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberCipherRows.getRow());
        } finally {
            if (amberCipherRows != null) {
                amberCipherRows.close();
            }
            if (amberCipherStatement != null) {
                amberCipherStatement.close();
            }
            amberCipherConnection.close();
        }
    }
}
