import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetCipher {

    public static String data;

    public void runVelvetCipher() throws SQLException {
        data = System.getenv("VELVET_CIPHER_FILTER");
        (new CWE89_P10_V1_VelvetCipherSink()).queryVelvetCipher();
    }
}

class CWE89_P10_V1_VelvetCipherSink {
    public void queryVelvetCipher() throws SQLException {
        String data = CWE89_P10_V1_VelvetCipher.data;
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
