import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_VelvetCipher {

    public void runVelvetCipher() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = (new CWE89_P07_V2_VelvetCipherSource()).loadVelvetCipher();
        }
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

class CWE89_P07_V2_VelvetCipherSource {
    public String loadVelvetCipher() {
        String data;
        data = System.getenv("VELVET_CIPHER_FILTER");
        return data;
    }
}
