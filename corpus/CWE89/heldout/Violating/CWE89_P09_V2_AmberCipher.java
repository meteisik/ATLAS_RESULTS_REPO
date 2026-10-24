import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_AmberCipher {

    static class Container {
        public String containerOne;
    }

    public void runAmberCipher() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("AMBER_CIPHER_FILTER");
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_AmberCipherSink()).queryAmberCipher(dataContainer);
    }
}

class CWE89_P09_V2_AmberCipherSink {
    public void queryAmberCipher(CWE89_P09_V2_AmberCipher.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
