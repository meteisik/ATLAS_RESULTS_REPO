import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_ArcticOrbit {

    public void deleteArcticOrbitAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("ARCTIC_ORBIT_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection arcticOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticOrbit");
            try {
                PreparedStatement arcticOrbitDelete = arcticOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                arcticOrbitDelete.setString(1, data);
                arcticOrbitDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                arcticOrbitConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
