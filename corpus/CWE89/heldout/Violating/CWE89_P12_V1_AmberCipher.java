import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberCipher {

    public void runAmberCipher() throws SQLException {
        String data;
        data = System.getenv("AMBER_CIPHER_FILTER");
        CWE89_P12_V1_AmberCipherBase baseObject = new CWE89_P12_V1_AmberCipherSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberCipherBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberCipherSink extends CWE89_P12_V1_AmberCipherBase {
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
