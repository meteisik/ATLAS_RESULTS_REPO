import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberCipher {

    public static String data;

    public void runAmberCipher() throws SQLException {
        if (true) {
            data = System.getenv("AMBER_CIPHER_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AmberCipherSink()).queryAmberCipher();
    }
}

class CWE89_P10_V2_AmberCipherSink {
    public void queryAmberCipher() throws SQLException {
        String data = CWE89_P10_V2_AmberCipher.data;
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
