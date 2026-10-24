import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadeCascadeSafe {

    public void deleteJadeCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_CASCADE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadeCascadeSafeSink()).applyJadeCascadeDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadeCascadeSafeSink {
    public void applyJadeCascadeDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeCascade");
        try {
            PreparedStatement jadeCascadeDelete = jadeCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeCascadeDelete.setString(1, data);
            if (authorized) {
                jadeCascadeDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            jadeCascadeConnection.close();
        }
    }
}
