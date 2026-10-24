import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadeSundialSafe {

    public void deleteJadeSundialAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_SUNDIAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadeSundialSafeSink()).applyJadeSundialDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadeSundialSafeSink {
    public void applyJadeSundialDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSundial");
        try {
            PreparedStatement jadeSundialDelete = jadeSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeSundialDelete.setString(1, data);
            if (authorized) {
                jadeSundialDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            jadeSundialConnection.close();
        }
    }
}
