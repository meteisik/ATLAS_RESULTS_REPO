import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VelvetCipher {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void runVelvetCipher() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("VELVET_CIPHER_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VelvetCipherSink()).queryVelvetCipher(dataContainer);
    }
}

class CWE89_P09_V2_VelvetCipherSink {
    public void queryVelvetCipher(CWE89_P09_V2_VelvetCipher.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
