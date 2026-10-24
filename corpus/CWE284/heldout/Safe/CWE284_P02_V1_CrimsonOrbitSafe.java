import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_CrimsonOrbitSafe {

    public void deleteCrimsonOrbitAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("CRIMSON_ORBIT_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection crimsonOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonOrbit");
            try {
                PreparedStatement crimsonOrbitDelete = crimsonOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                crimsonOrbitDelete.setString(1, data);
                if (authorized) {
                    crimsonOrbitDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                crimsonOrbitConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
